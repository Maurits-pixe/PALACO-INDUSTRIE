#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_office_event_contract::{EventEnvelope, ExecutionState, AuthorizationState};
use palaco_office_execution_safety::{pre_side_effect_check, ClaimDecision, IdempotencyRegistry, SafetyError};

/// Adapter-level failure. All failures prevent external execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    /// Event failed validation.
    InvalidEvent(String),
    /// Authorization is not executable.
    AuthorizationNotGranted,
    /// Authorization reference is missing.
    AuthorizationReferenceMissing,
    /// Execution has not been committed.
    ExecutionNotStarted,
    /// Execution is terminal or blocked.
    ExecutionTerminal,
    /// Idempotency claim was already consumed.
    DuplicateIdempotencyKey,
    /// No proposed action exists.
    ActionMissing,
    /// Action type is empty.
    ActionTypeMissing,
    /// Destination is empty.
    DestinationMissing,
}

/// Result of adapter preflight; no external side effect occurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterPreflight {
    /// Event identifier.
    pub event_id: String,
    /// Authorization reference.
    pub authorization_reference: String,
    /// Destination to which an adapter may later dispatch.
    pub destination: String,
    /// Idempotency key claimed for this execution.
    pub idempotency_key: String,
}

/// Production adapter boundary. Implementations remain responsible for the actual external API call.
pub trait ExecutionAdapter {
    /// Performs the external operation after the caller has passed the safety boundary.
    fn execute(&self, preflight: &AdapterPreflight, event: &EventEnvelope) -> Result<Option<String>, AdapterError>;
}

/// Performs all PALACO checks immediately before adapter dispatch.
pub fn preflight(event: &EventEnvelope, registry: &mut IdempotencyRegistry) -> Result<AdapterPreflight, AdapterError> {
    let claim = pre_side_effect_check(event, registry).map_err(map_safety_error)?;
    if !matches!(claim, ClaimDecision::Claimed) {
        return Err(AdapterError::DuplicateIdempotencyKey);
    }
    let action = event.proposed_action.as_ref().ok_or(AdapterError::ActionMissing)?;
    if action.action_type.trim().is_empty() { return Err(AdapterError::ActionTypeMissing); }
    if action.destination.trim().is_empty() { return Err(AdapterError::DestinationMissing); }
    let reference = event.authorization.reference.clone().ok_or(AdapterError::AuthorizationReferenceMissing)?;
    Ok(AdapterPreflight {
        event_id: event.event_id.clone(),
        authorization_reference: reference,
        destination: action.destination.clone(),
        idempotency_key: event.idempotency_key.clone(),
    })
}

fn map_safety_error(error: SafetyError) -> AdapterError {
    match error {
        SafetyError::InvalidEvent(value) => AdapterError::InvalidEvent(value),
        SafetyError::AuthorizationNotExecutable => AdapterError::AuthorizationNotGranted,
        SafetyError::AuthorizationReferenceMissing => AdapterError::AuthorizationReferenceMissing,
        SafetyError::ExecutionNotStarted => AdapterError::ExecutionNotStarted,
        SafetyError::ExecutionTerminal => AdapterError::ExecutionTerminal,
        SafetyError::DuplicateIdempotencyKey => AdapterError::DuplicateIdempotencyKey,
        SafetyError::EmptyIdempotencyKey => AdapterError::InvalidEvent("idempotency_key is empty".into()),
    }
}

/// Explicitly verifies the authorization/execution state at adapter entry.
pub fn verify_adapter_entry(event: &EventEnvelope) -> Result<(), AdapterError> {
    event.validate().map_err(AdapterError::InvalidEvent)?;
    if !matches!(event.authorization.state, AuthorizationState::Granted) {
        return Err(AdapterError::AuthorizationNotGranted);
    }
    if event.authorization.reference.as_deref().map(str::trim).filter(|v| !v.is_empty()).is_none() {
        return Err(AdapterError::AuthorizationReferenceMissing);
    }
    if !matches!(event.execution, ExecutionState::Started) {
        return Err(match event.execution {
            ExecutionState::NotStarted => AdapterError::ExecutionNotStarted,
            ExecutionState::Completed | ExecutionState::Failed | ExecutionState::Blocked => AdapterError::ExecutionTerminal,
            ExecutionState::Started => unreachable!(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use palaco_office_event_contract::{Authorization, ExecutionState, ProposedAction};

    fn event() -> EventEnvelope {
        EventEnvelope {
            event_id: "event-022".into(),
            authorization: Authorization { state: AuthorizationState::Granted, reference: Some("auth-022".into()) },
            execution: ExecutionState::Started,
            trace_id: "trace-022".into(),
            idempotency_key: "idem-022".into(),
            proposed_action: Some(ProposedAction { action_type: "create_task".into(), destination: "todo".into() }),
            evidence_ref: "evidence-022".into(),
            source_ref: "graph:message-022".into(),
        }
    }

    #[test]
    fn revoked_event_cannot_enter_adapter() {
        let mut e=event(); e.authorization.state=AuthorizationState::Revoked;
        assert_eq!(verify_adapter_entry(&e),Err(AdapterError::AuthorizationNotGranted));
    }

    #[test]
    fn preflight_claims_once() -> Result<(), AdapterError> {
        let e=event(); let mut r=IdempotencyRegistry::default();
        let p=preflight(&e,&mut r)?;
        assert_eq!(p.event_id,"event-022");
        assert_eq!(preflight(&e,&mut r),Err(AdapterError::DuplicateIdempotencyKey));
        Ok(())
    }
}
