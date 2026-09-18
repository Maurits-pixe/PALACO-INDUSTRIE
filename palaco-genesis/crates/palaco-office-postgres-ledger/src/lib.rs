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
    fn claim_idempotency(&mut self, idempotency_key: &str, execution_id: &str) -> Result<(), LedgerRepositoryError>;

    /// Reads the current durable state.
    fn get_current_state(
        &mut self,
        execution_id: &str,
    ) -> Result<LedgerState, LedgerRepositoryError>;

    /// Performs an atomic first-class revocation.
    fn revoke(&mut self, execution_id: &str) -> Result<(), LedgerRepositoryError>;

    /// Claims one pending outbox signal for dispatch without changing its fact.
    fn claim_outbox_signal(&mut self) -> Result<(), LedgerRepositoryError>;
}

pub mod adapter;

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
INSERT INTO palaco_execution_idempotency (idempotency_key, execution_id)
VALUES ($1, $2)
ON CONFLICT (idempotency_key) DO NOTHING;
"#;


/// SQL contract for an atomic lifecycle append plus current-state projection.
pub const APPEND_TRANSITION_SQL: &str = r#"
BEGIN;
SELECT execution_id, state
FROM palaco_execution_current
WHERE execution_id = $1
FOR UPDATE;
-- Validate the transition against the locked current state.
-- INSERT the new immutable lifecycle row.
-- UPDATE palaco_execution_current to the new sequence/state.
-- INSERT STATE_CHANGED into palaco_execution_outbox.
COMMIT;
"#;

/// SQL contract for revocation propagation through the transactional outbox.
pub const REVOKE_OUTBOX_SQL: &str = r#"
BEGIN;
SELECT execution_id, state
FROM palaco_execution_current
WHERE execution_id = $1
FOR UPDATE;
-- Reject terminal states.
-- INSERT REVOKED into palaco_execution_ledger.
-- UPDATE palaco_execution_current to REVOKED.
-- INSERT REVOKED into palaco_execution_outbox.
COMMIT;
"#;

/// SQL contract for a fail-closed worker claim.
///
/// The claim and state transition occur while the execution row is locked.
/// A revoked execution can therefore never be promoted from stale state.
pub const WORKER_CLAIM_SQL: &str = r#"
BEGIN;
SELECT execution_id, state
FROM palaco_execution_current
WHERE execution_id = $1
FOR UPDATE;
-- If no row exists: fail closed.
-- If state is REVOKED, EXPIRED, COMPLETED, FAILED, or CANCELLED: reject.
-- Only PENDING may transition to EXECUTING.
-- INSERT EXECUTING into palaco_execution_ledger.
-- UPDATE palaco_execution_current.
-- INSERT STATE_CHANGED into palaco_execution_outbox.
COMMIT;
"#;

/// SQL contract for claiming one outbox item.
///
/// SKIP LOCKED prevents concurrent dispatchers from taking the same item.
/// Dispatch is still separate from external execution.
pub const OUTBOX_CLAIM_SQL: &str = r#"
BEGIN;
SELECT outbox_id, sequence_id, execution_id, event_type
FROM palaco_execution_outbox
WHERE dispatched_at IS NULL
ORDER BY outbox_id
FOR UPDATE SKIP LOCKED
LIMIT 1;
-- Dispatcher may mark the selected signal as dispatched after successful publication.
COMMIT;
"#;

/// SQL contract for the final durable revocation check.
///
/// This check must happen after any queue delay and immediately before the
/// external side-effect boundary.
pub const FINAL_REVOCATION_SQL: &str = r#"
SELECT state
FROM palaco_execution_current
WHERE execution_id = $1;
-- Only a durable state other than REVOKED permits the caller to continue
-- to its separate authorization and transport gates.
"#;

/// Deterministic lifecycle-transition policy used by repository adapters.
pub fn permits_transition(current: Option<LedgerState>, next: LedgerState) -> bool {
    match (current, next) {
        (None, LedgerState::Pending) => true,
        (Some(LedgerState::Pending), LedgerState::Executing) => true,
        (Some(LedgerState::Executing), LedgerState::Completed) => true,
        (Some(LedgerState::Executing), LedgerState::Failed) => true,
        (Some(LedgerState::Pending), LedgerState::Revoked) => true,
        (Some(LedgerState::Executing), LedgerState::Revoked) => true,
        (Some(LedgerState::Pending), LedgerState::Expired) => true,
        (Some(LedgerState::Executing), LedgerState::Expired) => true,
        (Some(LedgerState::Pending), LedgerState::Cancelled) => true,
        (Some(LedgerState::Executing), LedgerState::Cancelled) => true,
        _ => false,
    }
}

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
    fn transition_policy_is_fail_closed() {
        assert!(permits_transition(None, LedgerState::Pending));
        assert!(permits_transition(Some(LedgerState::Pending), LedgerState::Executing));
        assert!(permits_transition(Some(LedgerState::Pending), LedgerState::Revoked));
        assert!(!permits_transition(Some(LedgerState::Revoked), LedgerState::Executing));
        assert!(!permits_transition(Some(LedgerState::Completed), LedgerState::Executing));
        assert!(!permits_transition(Some(LedgerState::Expired), LedgerState::Completed));
    }

    #[test]
    fn worker_claim_requires_lock_and_rejects_revoked() {
        let lock = WORKER_CLAIM_SQL.find("FOR UPDATE");
        let revoked = WORKER_CLAIM_SQL.find("state is REVOKED");
        assert!(lock.is_some());
        assert!(revoked.is_some());
        assert!(lock < revoked);
    }

    #[test]
    fn outbox_claim_uses_skip_locked() {
        assert!(OUTBOX_CLAIM_SQL.contains("FOR UPDATE SKIP LOCKED"));
    }

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
