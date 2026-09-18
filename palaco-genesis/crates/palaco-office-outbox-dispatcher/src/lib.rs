#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Crash-safe transactional outbox dispatcher boundary.

use postgres::{Client, NoTls};

/// A leased outbox signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxLease {
    /// Durable outbox identity.
    pub outbox_id: i64,
    /// Lifecycle sequence identity.
    pub sequence_id: i64,
    /// Execution identity.
    pub execution_id: String,
    /// Propagation event type.
    pub event_type: String,
    /// Lease owner.
    pub worker_id: String,
}

/// Dispatcher error; callers must fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatcherError {
    /// No signal was available.
    NoSignal,
    /// The lease owner did not match.
    LeaseOwnerMismatch,
    /// Database failure.
    Database(String),
}

/// PostgreSQL-backed outbox dispatcher.
pub struct OutboxDispatcher {
    client: Client,
    lease_seconds: i64,
}

impl OutboxDispatcher {
    /// Connects to PostgreSQL.
    pub fn connect(connection_string: &str, lease_seconds: i64) -> Result<Self, DispatcherError> {
        if lease_seconds <= 0 {
            return Err(DispatcherError::Database("lease duration must be positive".into()));
        }
        Client::connect(connection_string, NoTls)
            .map(|client| Self { client, lease_seconds })
            .map_err(|e| DispatcherError::Database(e.to_string()))
    }

    /// Wraps an authenticated database client.
    pub fn from_client(client: Client, lease_seconds: i64) -> Result<Self, DispatcherError> {
        if lease_seconds <= 0 {
            return Err(DispatcherError::Database("lease duration must be positive".into()));
        }
        Ok(Self { client, lease_seconds })
    }

    /// Atomically leases one pending or expired signal.
    pub fn lease_one(&mut self, worker_id: &str) -> Result<OutboxLease, DispatcherError> {
        if worker_id.trim().is_empty() {
            return Err(DispatcherError::Database("worker identity is required".into()));
        }
        let mut tx = self.client.transaction().map_err(|e| DispatcherError::Database(e.to_string()))?;
        let row = tx.query_opt(
            "SELECT outbox_id,sequence_id,execution_id,event_type FROM palaco_execution_outbox WHERE dispatched_at IS NULL AND (lease_until IS NULL OR lease_until <= CURRENT_TIMESTAMP) ORDER BY outbox_id FOR UPDATE SKIP LOCKED LIMIT 1",
            &[],
        ).map_err(|e| DispatcherError::Database(e.to_string()))?;
        let row = row.ok_or(DispatcherError::NoSignal)?;
        let outbox_id: i64 = row.get(0);
        let sequence_id: i64 = row.get(1);
        let execution_id: String = row.get(2);
        let event_type: String = row.get(3);
        let changed = tx.execute(
            "UPDATE palaco_execution_outbox SET leased_by=$2,lease_until=CURRENT_TIMESTAMP + ($3 * INTERVAL '1 second') WHERE outbox_id=$1 AND dispatched_at IS NULL AND (lease_until IS NULL OR lease_until <= CURRENT_TIMESTAMP)",
            &[&outbox_id,&worker_id,&self.lease_seconds],
        ).map_err(|e| DispatcherError::Database(e.to_string()))?;
        if changed != 1 {
            return Err(DispatcherError::Database("lease acquisition lost race".into()));
        }
        tx.commit().map_err(|e| DispatcherError::Database(e.to_string()))?;
        Ok(OutboxLease { outbox_id, sequence_id, execution_id, event_type, worker_id: worker_id.to_owned() })
    }

    /// Acknowledges a signal only for the worker holding its active lease.
    pub fn acknowledge(&mut self, lease: &OutboxLease) -> Result<(), DispatcherError> {
        let changed = self.client.execute(
            "UPDATE palaco_execution_outbox SET dispatched_at=CURRENT_TIMESTAMP,leased_by=NULL,lease_until=NULL WHERE outbox_id=$1 AND leased_by=$2 AND dispatched_at IS NULL",
            &[&lease.outbox_id,&lease.worker_id],
        ).map_err(|e| DispatcherError::Database(e.to_string()))?;
        if changed == 1 { Ok(()) } else { Err(DispatcherError::LeaseOwnerMismatch) }
    }
}

/// External publication is intentionally not implemented here.
///
/// A publisher must receive an OutboxLease, publish the signal, and only then
/// call acknowledge. It must never execute the underlying office action.
