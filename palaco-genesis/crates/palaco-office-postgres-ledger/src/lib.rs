#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! PostgreSQL persistence contract for the PALACO execution ledger.
//!
//! This crate deliberately defines the repository boundary without opening a
//! database connection. Connection pooling, credentials, and runtime I/O belong
//! to the infrastructure composition layer.

use palaco_office_execution_safety::LedgerState;

/// Persistence-layer failure. Callers must fail closed on every variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerRepositoryError {
    /// The requested execution does not exist.
    ExecutionNotFound,
    /// The requested lifecycle transition is not legal.
    InvalidTransition,
    /// A durable idempotency key already exists.
    DuplicateIdempotencyKey,
    /// The persistence transaction could not be committed.
    TransactionFailed(String),
}

/// Durable execution row used by repository adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableExecution {
    /// Stable execution identity.
    pub execution_id: String,
    /// PALACO event identity.
    pub event_id: String,
    /// Trace identity.
    pub trace_id: String,
    /// Idempotency identity.
    pub idempotency_key: String,
    /// Authorization reference, when known.
    pub authorization_reference: Option<String>,
    /// Current lifecycle state.
    pub state: LedgerState,
}

/// Repository boundary for a transactional PostgreSQL implementation.
pub trait ExecutionLedgerRepository {
    /// Appends a transition and updates the current-state projection atomically.
    fn append_transition(
        &mut self,
        execution: DurableExecution,
    ) -> Result<(), LedgerRepositoryError>;

    /// Atomically claims an idempotency key.
    fn claim_idempotency(&mut self, idempotency_key: &str) -> Result<(), LedgerRepositoryError>;

    /// Reads the current durable state.
    fn get_current_state(
        &mut self,
        execution_id: &str,
    ) -> Result<LedgerState, LedgerRepositoryError>;

    /// Performs an atomic first-class revocation.
    fn revoke(&mut self, execution_id: &str) -> Result<(), LedgerRepositoryError>;
}

/// SQL contract for a worker claim.
///
/// The FOR UPDATE lock is intentional: a worker must re-read durable state
/// under the same lock used by revocation before it can transition work.
pub const CLAIM_SQL: &str = r#"
BEGIN;
SELECT execution_id, state
FROM palaco_execution_current
WHERE execution_id = $1
FOR UPDATE;
-- Application layer rejects REVOKED and other terminal states.
-- Application layer then appends EXECUTING and updates the projection.
COMMIT;
"#;

/// SQL contract for first-class revocation.
///
/// No external side effect occurs inside this transaction.
pub const REVOKE_SQL: &str = r#"
BEGIN;
SELECT execution_id, state
FROM palaco_execution_current
WHERE execution_id = $1
FOR UPDATE;
-- Application layer rejects already-terminal transitions.
-- Append REVOKED to palaco_execution_ledger.
-- Update palaco_execution_current to REVOKED.
-- Append REVOKED to palaco_execution_outbox.
COMMIT;
"#;

/// SQL contract for durable idempotency.
pub const IDEMPOTENCY_SQL: &str = r#"
INSERT INTO palaco_execution_ledger
    (execution_id, event_id, trace_id, idempotency_key, authorization_reference, state)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (idempotency_key) DO NOTHING;
"#;

/// Maps the domain state to the stable PostgreSQL representation.
pub fn state_name(state: LedgerState) -> &'static str {
    match state {
        LedgerState::Pending => "PENDING",
        LedgerState::Executing => "EXECUTING",
        LedgerState::Completed => "COMPLETED",
        LedgerState::Failed => "FAILED",
        LedgerState::Revoked => "REVOKED",
        LedgerState::Expired => "EXPIRED",
        LedgerState::Cancelled => "CANCELLED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_mapping_is_explicit() {
        assert_eq!(state_name(LedgerState::Pending), "PENDING");
        assert_eq!(state_name(LedgerState::Executing), "EXECUTING");
        assert_eq!(state_name(LedgerState::Revoked), "REVOKED");
        assert_eq!(state_name(LedgerState::Expired), "EXPIRED");
    }

    #[test]
    fn revoke_sql_locks_before_transition() {
        let lock = REVOKE_SQL.find("FOR UPDATE");
        let append = REVOKE_SQL.find("Append REVOKED");
        assert!(lock.is_some());
        assert!(append.is_some());
        assert!(lock < append);
    }
}
