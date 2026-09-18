#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashSet;
use palaco_office_event_contract::{AuthorizationState, EventEnvelope, ExecutionState};

/// Safety-layer failure; all failures are fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyError {
    /// Event failed validation.
    InvalidEvent(String),
    /// Authorization is not executable.
    AuthorizationNotExecutable,
    /// Authorization reference is absent.
    AuthorizationReferenceMissing,
    /// Execution has not been committed.
    ExecutionNotStarted,
    /// Execution is terminal or blocked.
    ExecutionTerminal,
    /// Idempotency key is already claimed.
    DuplicateIdempotencyKey,
    /// Idempotency key is empty.
    EmptyIdempotencyKey,
    /// Execution was revoked before the side effect boundary.
    RevokedExecution,
}

/// Result of an idempotency claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimDecision { Claimed, Duplicate }

/// In-memory reference implementation of exactly-once claim semantics.
#[derive(Debug, Default)]
pub struct IdempotencyRegistry { claimed: HashSet<String> }

impl IdempotencyRegistry {
    /// Claims a key once; duplicates never authorize a second execution.
    pub fn claim(&mut self, key: &str) -> Result<ClaimDecision, SafetyError> {
        let key = key.trim();
        if key.is_empty() { return Err(SafetyError::EmptyIdempotencyKey); }
        if self.claimed.insert(key.to_owned()) { Ok(ClaimDecision::Claimed) } else { Ok(ClaimDecision::Duplicate) }
    }
}

/// Lifecycle control for queued, pending, retryable execution.
///
/// Revocation is a first-class control signal. It is intentionally separate
/// from expiration and remains valid even after a request was signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionControl {
    /// Stable execution identity.
    pub execution_id: String,
    /// Trace identity retained across cancellation.
    pub trace_id: String,
    /// Whether queued work is currently revoked.
    pub revoked: bool,
    /// Number of retries that have been scheduled.
    pub scheduled_retries: u32,
}

impl ExecutionControl {
    /// Creates an active execution control record.
    pub fn new(execution_id: impl Into<String>, trace_id: impl Into<String>) -> Self {
        Self { execution_id: execution_id.into(), trace_id: trace_id.into(), revoked: false, scheduled_retries: 0 }
    }

    /// Propagates REVOKE to pending and retryable work.
    pub fn revoke(&mut self) {
        self.revoked = true;
        self.scheduled_retries = 0;
    }

    /// Records one retry only while execution remains active.
    pub fn schedule_retry(&mut self) -> Result<(), SafetyError> {
        if self.revoked { return Err(SafetyError::RevokedExecution); }
        self.scheduled_retries = self.scheduled_retries.saturating_add(1);
        Ok(())
    }

    /// Returns whether another execution attempt may proceed.
    pub fn permits_execution(&self) -> bool { !self.revoked }
}

/// Final revocation gate immediately before external transport.
pub fn revocation_check(control: &ExecutionControl) -> Result<(), SafetyError> {
    if control.revoked { Err(SafetyError::RevokedExecution) } else { Ok(()) }
}

/// Last safety boundary before an external side effect.
pub fn pre_side_effect_check(event: &EventEnvelope, registry: &mut IdempotencyRegistry) -> Result<ClaimDecision, SafetyError> {
    event.validate().map_err(SafetyError::InvalidEvent)?;
    match event.execution {
        ExecutionState::Started => {}
        ExecutionState::NotStarted => return Err(SafetyError::ExecutionNotStarted),
        ExecutionState::Completed | ExecutionState::Failed | ExecutionState::Blocked => return Err(SafetyError::ExecutionTerminal),
    }
    if !matches!(event.authorization.state, AuthorizationState::Granted) {
        return Err(SafetyError::AuthorizationNotExecutable);
    }
    if event.authorization.reference.as_deref().map(str::trim).filter(|v| !v.is_empty()).is_none() {
        return Err(SafetyError::AuthorizationReferenceMissing);
    }
    registry.claim(&event.idempotency_key)
}

/// Immutable execution receipt retaining authorization, trace and idempotency lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReceipt {
    /// Event identity.
    pub event_id: String,
    /// Authorization reference.
    pub authorization_reference: String,
    /// Trace identity.
    pub trace_id: String,
    /// Idempotency identity.
    pub idempotency_key: String,
    /// Optional external system reference.
    pub external_reference: Option<String>,
}

/// Builds a receipt only from a completed event.
pub fn completed_receipt(event: &EventEnvelope, external_reference: Option<String>) -> Result<ExecutionReceipt, SafetyError> {
    event.validate().map_err(SafetyError::InvalidEvent)?;
    if !matches!(event.execution, ExecutionState::Completed) { return Err(SafetyError::ExecutionNotStarted); }
    let reference = event.authorization.reference.clone().ok_or(SafetyError::AuthorizationReferenceMissing)?;
    Ok(ExecutionReceipt {
        event_id: event.event_id.clone(),
        authorization_reference: reference,
        trace_id: event.trace_id.clone(),
        idempotency_key: event.idempotency_key.clone(),
        external_reference,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use palaco_office_event_contract::{Authorization, ProposedAction};

    fn event() -> EventEnvelope {
        EventEnvelope {
            event_id: "event-021".into(),
            authorization: Authorization { state: AuthorizationState::Granted, reference: Some("auth-021".into()) },
            execution: ExecutionState::Started,
            trace_id: "trace-021".into(),
            idempotency_key: "idem-021".into(),
            proposed_action: Some(ProposedAction { action_type: "create_task".into(), destination: "todo".into() }),
            evidence_ref: "evidence-021".into(),
            source_ref: "graph:message-021".into(),
        }
    }

    #[test]
    fn duplicate_claim_is_blocked() -> Result<(), SafetyError> {
        let e = event(); let mut r = IdempotencyRegistry::default();
        assert_eq!(pre_side_effect_check(&e, &mut r)?, ClaimDecision::Claimed);
        assert_eq!(pre_side_effect_check(&e, &mut r)?, ClaimDecision::Duplicate);
        Ok(())
    }

    #[test]
    fn revoked_authorization_is_rechecked() {
        let mut e = event(); e.authorization.state = AuthorizationState::Revoked;
        let mut r = IdempotencyRegistry::default();
        assert_eq!(pre_side_effect_check(&e, &mut r), Err(SafetyError::AuthorizationNotExecutable));
    }

    #[test]
    fn expired_authorization_is_not_executable() {
        let mut e = event(); e.authorization.state = AuthorizationState::Expired;
        let mut r = IdempotencyRegistry::default();
        assert_eq!(pre_side_effect_check(&e, &mut r), Err(SafetyError::AuthorizationNotExecutable));
    }

    #[test]
    fn receipt_preserves_lineage() -> Result<(), SafetyError> {
        let mut e = event(); e.execution = ExecutionState::Completed;
        let receipt = completed_receipt(&e, Some("graph:task-021".into()))?;
        assert_eq!(receipt.authorization_reference, "auth-021");
        assert_eq!(receipt.trace_id, "trace-021");
        assert_eq!(receipt.external_reference.as_deref(), Some("graph:task-021"));
        Ok(())
    }
}
