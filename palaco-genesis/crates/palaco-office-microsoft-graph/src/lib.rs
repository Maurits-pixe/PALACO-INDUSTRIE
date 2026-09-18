#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_office_event_contract::{AuthorizationState, EventEnvelope, ExecutionState};
use palaco_office_execution_safety::{pre_side_effect_check, ClaimDecision, IdempotencyRegistry, SafetyError};

/// HTTP method required by a Microsoft Graph execution request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphMethod {
    /// HTTP POST.
    Post,
}

/// A fully bounded Microsoft Graph request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphRequest {
    /// HTTP method.
    pub method: GraphMethod,
    /// Graph resource path, without host or query string.
    pub path: String,
    /// JSON request body. The adapter does not serialize or send it.
    pub body: String,
    /// PALACO event identifier.
    pub event_id: String,
    /// PALACO trace identifier.
    pub trace_id: String,
    /// Authorization reference bound to this request.
    pub authorization_reference: String,
    /// Claimed idempotency key.
    pub idempotency_key: String,
}

/// Result returned by a transport after Microsoft Graph accepts the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphTransportResult {
    /// External Microsoft Graph object identifier, when supplied by the API.
    pub external_reference: Option<String>,
}

/// Transport boundary for Microsoft Graph.
///
/// Implementations may perform network I/O. This crate supplies the
/// constitutional checks and request construction; it does not contain
/// credentials, network clients, or implicit authorization.
pub trait GraphTransport {
    /// Sends one already-authorized Graph request.
    fn send(&self, request: &GraphRequest) -> Result<GraphTransportResult, GraphAdapterError>;
}

/// Microsoft Graph adapter errors. Every error blocks external execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphAdapterError {
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
    /// Idempotency key has already been consumed.
    DuplicateIdempotencyKey,
    /// Proposed action is missing.
    ActionMissing,
    /// Action type is unsupported.
    UnsupportedAction(String),
    /// Action destination is missing.
    DestinationMissing,
    /// Transport rejected or failed the request.
    Transport(String),
}

/// Receipt for an accepted external operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphExecutionReceipt {
    /// PALACO event identifier.
    pub event_id: String,
    /// PALACO trace identifier.
    pub trace_id: String,
    /// Authorization reference.
    pub authorization_reference: String,
    /// Idempotency key.
    pub idempotency_key: String,
    /// External Graph object reference, when available.
    pub external_reference: Option<String>,
}

/// Builds the Graph request for a supported PALACO action.
///
/// The initial supported action is `create_task` targeting Microsoft To Do.
/// The destination must be `todo`; list identifiers and task payload remain
/// in the caller-controlled JSON body and are never inferred by the adapter.
pub fn build_request(
    event: &EventEnvelope,
    authorization_reference: &str,
) -> Result<GraphRequest, GraphAdapterError> {
    event.validate().map_err(GraphAdapterError::InvalidEvent)?;
    if !matches!(event.authorization.state, AuthorizationState::Granted) {
        return Err(GraphAdapterError::AuthorizationNotGranted);
    }
    if authorization_reference.trim().is_empty() {
        return Err(GraphAdapterError::AuthorizationReferenceMissing);
    }
    if !matches!(event.execution, ExecutionState::Started) {
        return Err(match event.execution {
            ExecutionState::NotStarted => GraphAdapterError::ExecutionNotStarted,
            ExecutionState::Completed | ExecutionState::Failed | ExecutionState::Blocked => GraphAdapterError::ExecutionTerminal,
            ExecutionState::Started => unreachable!(),
        });
    }

    let action = event.proposed_action.as_ref().ok_or(GraphAdapterError::ActionMissing)?;
    if action.destination.trim().is_empty() {
        return Err(GraphAdapterError::DestinationMissing);
    }

    let path = match (action.action_type.as_str(), action.destination.as_str()) {
        ("create_task", "todo") => "/me/todo/lists/{list-id}/tasks".to_string(),
        (action_type, _) => return Err(GraphAdapterError::UnsupportedAction(action_type.to_string())),
    };

    Ok(GraphRequest {
        method: GraphMethod::Post,
        path,
        body: action.destination.clone(),
        event_id: event.event_id.clone(),
        trace_id: event.trace_id.clone(),
        authorization_reference: authorization_reference.to_string(),
        idempotency_key: event.idempotency_key.clone(),
    })
}

/// Concrete orchestration boundary for Microsoft Graph.
///
/// `execute` performs the PALACO safety re-check, claims idempotency, builds
/// the bounded request, and only then calls the injected transport.
pub struct MicrosoftGraphExecutionAdapter<T> {
    transport: T,
}

impl<T> MicrosoftGraphExecutionAdapter<T> {
    /// Creates an adapter around an explicit Graph transport.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<T: GraphTransport> MicrosoftGraphExecutionAdapter<T> {
    /// Executes one operation through the transport after all checks pass.
    pub fn execute(
        &mut self,
        event: &EventEnvelope,
        registry: &mut IdempotencyRegistry,
    ) -> Result<GraphExecutionReceipt, GraphAdapterError> {
        let claim = pre_side_effect_check(event, registry).map_err(map_safety_error)?;
        if !matches!(claim, ClaimDecision::Claimed) {
            return Err(GraphAdapterError::DuplicateIdempotencyKey);
        }

        let authorization_reference = event
            .authorization
            .reference
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or(GraphAdapterError::AuthorizationReferenceMissing)?;

        let request = build_request(event, authorization_reference)?;
        let result = self.transport.send(&request)?;
        Ok(GraphExecutionReceipt {
            event_id: event.event_id.clone(),
            trace_id: event.trace_id.clone(),
            authorization_reference: authorization_reference.to_string(),
            idempotency_key: event.idempotency_key.clone(),
            external_reference: result.external_reference,
        })
    }
}

fn map_safety_error(error: SafetyError) -> GraphAdapterError {
    match error {
        SafetyError::InvalidEvent(value) => GraphAdapterError::InvalidEvent(value),
        SafetyError::AuthorizationNotExecutable => GraphAdapterError::AuthorizationNotGranted,
        SafetyError::AuthorizationReferenceMissing => GraphAdapterError::AuthorizationReferenceMissing,
        SafetyError::ExecutionNotStarted => GraphAdapterError::ExecutionNotStarted,
        SafetyError::ExecutionTerminal => GraphAdapterError::ExecutionTerminal,
        SafetyError::DuplicateIdempotencyKey => GraphAdapterError::DuplicateIdempotencyKey,
        SafetyError::EmptyIdempotencyKey => GraphAdapterError::InvalidEvent("idempotency_key is empty".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use palaco_office_event_contract::{Authorization, ProposedAction};

    #[derive(Default)]
    struct RecordingTransport {
        calls: usize,
    }

    impl GraphTransport for RecordingTransport {
        fn send(&self, _request: &GraphRequest) -> Result<GraphTransportResult, GraphAdapterError> {
            Ok(GraphTransportResult { external_reference: Some("graph-object-023".into()) })
        }
    }

    fn event() -> EventEnvelope {
        EventEnvelope {
            event_id: "event-023".into(),
            authorization: Authorization { state: AuthorizationState::Granted, reference: Some("auth-023".into()) },
            execution: ExecutionState::Started,
            trace_id: "trace-023".into(),
            idempotency_key: "idem-023".into(),
            proposed_action: Some(ProposedAction { action_type: "create_task".into(), destination: "todo".into() }),
            evidence_ref: "evidence-023".into(),
            source_ref: "graph:message-023".into(),
        }
    }

    #[test]
    fn request_is_bounded_to_todo_task_creation() -> Result<(), GraphAdapterError> {
        let request = build_request(&event(), "auth-023")?;
        assert_eq!(request.method, GraphMethod::Post);
        assert_eq!(request.path, "/me/todo/lists/{list-id}/tasks");
        assert_eq!(request.authorization_reference, "auth-023");
        Ok(())
    }

    #[test]
    fn revoked_event_is_blocked_before_request_construction() {
        let mut e = event();
        e.authorization.state = AuthorizationState::Revoked;
        assert_eq!(
            build_request(&e, "auth-023"),
            Err(GraphAdapterError::AuthorizationNotGranted)
        );
    }

    #[test]
    fn duplicate_idempotency_is_blocked_before_transport() {
        let mut registry = IdempotencyRegistry::default();
        let mut adapter = MicrosoftGraphExecutionAdapter::new(RecordingTransport::default());
        let first = adapter.execute(&event(), &mut registry);
        assert_eq!(first.map(|r| r.external_reference), Ok(Some("graph-object-023".into())));
        assert_eq!(
            adapter.execute(&event(), &mut registry),
            Err(GraphAdapterError::DuplicateIdempotencyKey)
        );
    }
}
