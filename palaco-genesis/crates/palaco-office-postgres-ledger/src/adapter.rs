#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Concrete PostgreSQL execution-ledger adapter.

use postgres::{Client, NoTls};
use palaco_office_execution_safety::LedgerState;
use crate::{permits_transition, state_name, DurableExecution, ExecutionLedgerRepository, LedgerRepositoryError};

/// PostgreSQL-backed implementation of the PALACO execution-ledger boundary.
///
/// The database client is owned by this adapter; credentials and pooling policy
/// remain the responsibility of the composition layer.
pub struct PostgresExecutionLedger {
    client: Client,
}

impl PostgresExecutionLedger {
    /// Opens a PostgreSQL connection using the supplied connection string.
    pub fn connect(connection_string: &str) -> Result<Self, LedgerRepositoryError> {
        Client::connect(connection_string, NoTls)
            .map(|client| Self { client })
            .map_err(|e| LedgerRepositoryError::TransactionFailed(e.to_string()))
    }

    /// Wraps an already connected client.
    pub fn from_client(client: Client) -> Self {
        Self { client }
    }

    fn decode_state(value: String) -> Result<LedgerState, LedgerRepositoryError> {
        match value.as_str() {
            "PENDING" => Ok(LedgerState::Pending),
            "EXECUTING" => Ok(LedgerState::Executing),
            "COMPLETED" => Ok(LedgerState::Completed),
            "FAILED" => Ok(LedgerState::Failed),
            "REVOKED" => Ok(LedgerState::Revoked),
            "EXPIRED" => Ok(LedgerState::Expired),
            "CANCELLED" => Ok(LedgerState::Cancelled),
            _ => Err(LedgerRepositoryError::TransactionFailed("unknown durable state".into())),
        }
    }

    fn db_error(error: postgres::Error) -> LedgerRepositoryError {
        LedgerRepositoryError::TransactionFailed(error.to_string())
    }
}

impl ExecutionLedgerRepository for PostgresExecutionLedger {
    fn append_transition(&mut self, execution: DurableExecution) -> Result<(), LedgerRepositoryError> {
        let mut tx = self.client.transaction().map_err(Self::db_error)?;
        let row = tx.query_opt(
            "SELECT state FROM palaco_execution_current WHERE execution_id=$1 FOR UPDATE",
            &[&execution.execution_id],
        ).map_err(Self::db_error)?;
        let current = match row {
            Some(row) => Some(Self::decode_state(row.get::<_, String>(0))?),
            None => None,
        };
        if !permits_transition(current, execution.state) {
            return Err(LedgerRepositoryError::InvalidTransition);
        }
        let row = tx.query_one(
            "INSERT INTO palaco_execution_ledger (execution_id,event_id,trace_id,idempotency_key,authorization_reference,state) VALUES ($1,$2,$3,$4,$5,$6) RETURNING sequence_id",
            &[&execution.execution_id,&execution.event_id,&execution.trace_id,&execution.idempotency_key,&execution.authorization_reference,&state_name(execution.state)],
        ).map_err(Self::db_error)?;
        let sequence_id: i64 = row.get(0);
        tx.execute(
            "INSERT INTO palaco_execution_current (execution_id,sequence_id,state) VALUES ($1,$2,$3) ON CONFLICT (execution_id) DO UPDATE SET sequence_id=EXCLUDED.sequence_id,state=EXCLUDED.state,updated_at=CURRENT_TIMESTAMP",
            &[&execution.execution_id,&sequence_id,&state_name(execution.state)],
        ).map_err(Self::db_error)?;
        tx.execute(
            "INSERT INTO palaco_execution_outbox (sequence_id,execution_id,event_type) VALUES ($1,$2,'STATE_CHANGED')",
            &[&sequence_id,&execution.execution_id],
        ).map_err(Self::db_error)?;
        tx.commit().map_err(Self::db_error)
    }

    fn claim_idempotency(&mut self, idempotency_key: &str, execution_id: &str) -> Result<(), LedgerRepositoryError> {
        let count = self.client.execute(
            "INSERT INTO palaco_execution_idempotency (idempotency_key,execution_id) VALUES ($1,$2) ON CONFLICT (idempotency_key) DO NOTHING",
            &[&idempotency_key,&execution_id],
        ).map_err(Self::db_error)?;
        if count == 1 { Ok(()) } else { Err(LedgerRepositoryError::DuplicateIdempotencyKey) }
    }

    fn get_current_state(&mut self, execution_id: &str) -> Result<LedgerState, LedgerRepositoryError> {
        let row = self.client.query_opt(
            "SELECT state FROM palaco_execution_current WHERE execution_id=$1",
            &[&execution_id],
        ).map_err(Self::db_error)?.ok_or(LedgerRepositoryError::ExecutionNotFound)?;
        Self::decode_state(row.get(0))
    }

    fn revoke(&mut self, execution_id: &str) -> Result<(), LedgerRepositoryError> {
        let mut tx = self.client.transaction().map_err(Self::db_error)?;
        let current = tx.query_opt(
            "SELECT sequence_id,state FROM palaco_execution_current WHERE execution_id=$1 FOR UPDATE",
            &[&execution_id],
        ).map_err(Self::db_error)?.ok_or(LedgerRepositoryError::ExecutionNotFound)?;
        let state = Self::decode_state(current.get(1))?;
        if !permits_transition(Some(state), LedgerState::Revoked) {
            return Err(LedgerRepositoryError::InvalidTransition);
        }
        let sequence_id: i64 = current.get(0);
        let prior = tx.query_one(
            "SELECT event_id,trace_id,idempotency_key,authorization_reference FROM palaco_execution_ledger WHERE sequence_id=$1",
            &[&sequence_id],
        ).map_err(Self::db_error)?;
        let event_id: String = prior.get(0);
        let trace_id: String = prior.get(1);
        let idempotency_key: String = prior.get(2);
        let authorization_reference: Option<String> = prior.get(3);
        let row = tx.query_one(
            "INSERT INTO palaco_execution_ledger (execution_id,event_id,trace_id,idempotency_key,authorization_reference,state) VALUES ($1,$2,$3,$4,$5,'REVOKED') RETURNING sequence_id",
            &[&execution_id,&event_id,&trace_id,&idempotency_key,&authorization_reference],
        ).map_err(Self::db_error)?;
        let new_sequence: i64 = row.get(0);
        tx.execute(
            "UPDATE palaco_execution_current SET sequence_id=$2,state='REVOKED',updated_at=CURRENT_TIMESTAMP WHERE execution_id=$1",
            &[&execution_id,&new_sequence],
        ).map_err(Self::db_error)?;
        tx.execute(
            "INSERT INTO palaco_execution_outbox (sequence_id,execution_id,event_type) VALUES ($1,$2,'REVOKED')",
            &[&new_sequence,&execution_id],
        ).map_err(Self::db_error)?;
        tx.commit().map_err(Self::db_error)
    }

    fn claim_outbox_signal(&mut self) -> Result<(), LedgerRepositoryError> {
        let mut tx = self.client.transaction().map_err(Self::db_error)?;
        let row = tx.query_opt(
            "SELECT outbox_id FROM palaco_execution_outbox WHERE dispatched_at IS NULL ORDER BY outbox_id FOR UPDATE SKIP LOCKED LIMIT 1",
            &[],
        ).map_err(Self::db_error)?;
        let row = row.ok_or(LedgerRepositoryError::ExecutionNotFound)?;
        let outbox_id: i64 = row.get(0);
        tx.execute(
            "UPDATE palaco_execution_outbox SET dispatched_at=CURRENT_TIMESTAMP WHERE outbox_id=$1",
            &[&outbox_id],
        ).map_err(Self::db_error)?;
        tx.commit().map_err(Self::db_error)
    }
}
