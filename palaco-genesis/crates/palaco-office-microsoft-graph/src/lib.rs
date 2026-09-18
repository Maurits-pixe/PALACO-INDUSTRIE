#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod signature;

use palaco_office_event_contract::{AuthorizationState, EventEnvelope, ExecutionState};
use palaco_office_execution_safety::{pre_side_effect_check, revocation_check, ClaimDecision, ExecutionControl, IdempotencyRegistry, SafetyError};

/// HTTP method required by a Microsoft Graph execution request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphMethod { /// HTTP POST.\n    Post }

/// Transport-level outcome returned by a Microsoft Graph client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphTransportResult {
    /// HTTP status code returned by Microsoft Graph.
    pub status_code: u16,
    /// External Microsoft Graph object identifier, when supplied by the API.
    pub external_reference: Option<String>,
}

/// A fully bounded Microsoft Graph request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphRequest {
    /// HTTP method.
    pub method: GraphMethod,
    /// Graph resource path, without host or query string.
    pub path: String,
    /// Request body supplied by the caller.
    pub body: String,
    /// PALACO event identifier.
    pub event_id: String,
    /// PALACO trace identifier.
    pub trace_id: String,
    /// Authorization reference bound to this request.
    pub authorization_reference: String,
    /// Claimed idempotency key.
    pub idempotency_key: String,
    /// SHA-256 digest of the canonical request fields.
    pub integrity_hash: String,
    /// Source provenance reference inherited from the PALACO event.
    pub source_ref: String,
    /// Evidence reference inherited from the PALACO event.
    pub evidence_ref: String,
    /// Stable provenance reference bound to the signed request.
    pub provenance_reference: String,
}

/// Computes the canonical integrity digest for a bounded Graph request.
///
/// GO-028 makes the signature encoder the single canonical representation.
/// The legacy delimiter-based representation is therefore no longer used.
/// This preserves the rule: what is signed shall be exactly what is verified.
pub fn request_integrity_hash(request: &GraphRequest) -> String {
    signature::canonical_request_sha256(request)
}

/// Verifies that the request has not changed since its integrity hash was created.
pub fn verify_request_integrity(request: &GraphRequest) -> bool {
    request.integrity_hash == request_integrity_hash(request)
}

/// Transport boundary for Microsoft Graph.
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
    /// Execution was explicitly revoked.
    RevokedExecution,
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
    /// Microsoft Graph returned a non-success status.
    GraphRejected(u16),
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
    /// HTTP status returned by Microsoft Graph.
    pub status_code: u16,
    /// External Graph object reference, when available.
    pub external_reference: Option<String>,
}

/// Builds a bounded Graph request for the supported action.
///
/// No task payload is invented: the canonical event contract currently
/// contains action type and destination, but no task-payload contract.
pub fn build_request(event: &EventEnvelope, authorization_reference: &str) -> Result<GraphRequest, GraphAdapterError> {
    event.validate().map_err(GraphAdapterError::InvalidEvent)?;
    if !matches!(event.authorization.state, AuthorizationState::Granted) { return Err(GraphAdapterError::AuthorizationNotGranted); }
    if authorization_reference.trim().is_empty() { return Err(GraphAdapterError::AuthorizationReferenceMissing); }
    if !matches!(event.execution, ExecutionState::Started) {
        return Err(match event.execution {
            ExecutionState::NotStarted => GraphAdapterError::ExecutionNotStarted,
            ExecutionState::Completed | ExecutionState::Failed | ExecutionState::Blocked => GraphAdapterError::ExecutionTerminal,
            ExecutionState::Started => unreachable!(),
        });
    }
    let action = event.proposed_action.as_ref().ok_or(GraphAdapterError::ActionMissing)?;
    if action.destination.trim().is_empty() { return Err(GraphAdapterError::DestinationMissing); }
    let path = match (action.action_type.as_str(), action.destination.as_str()) {
        ("create_task", "todo") => "/me/todo/lists/{list-id}/tasks".to_string(),
        (action_type, _) => return Err(GraphAdapterError::UnsupportedAction(action_type.to_string())),
    };
    let mut request = GraphRequest {
        method: GraphMethod::Post,
        path,
        body: "{}".to_string(),
        event_id: event.event_id.clone(),
        trace_id: event.trace_id.clone(),
        authorization_reference: authorization_reference.to_string(),
        idempotency_key: event.idempotency_key.clone(),
        integrity_hash: String::new(),
        source_ref: event.source_ref.clone(),
        evidence_ref: event.evidence_ref.clone(),
        provenance_reference: format!("{}:{}", event.source_ref, event.event_id),
    };
    request.integrity_hash = request_integrity_hash(&request);
    Ok(request)
}


/// Builds a fully bound Microsoft To Do task request from a canonical payload.
///
/// The list identifier is supplied explicitly by the canonical payload; no
/// placeholder resource path is permitted.
pub fn build_task_request(
    event: &EventEnvelope,
    authorization_reference: &str,
    payload: &palaco_office_event_contract::TaskCreatePayload,
) -> Result<GraphRequest, GraphAdapterError> {
    let mut request = build_request(event, authorization_reference)?;
    let action = event.proposed_action.as_ref().ok_or(GraphAdapterError::ActionMissing)?;
    if action.action_type != "create_task" || action.destination != "todo" {
        return Err(GraphAdapterError::UnsupportedAction(action.action_type.clone()));
    }
    payload.validate().map_err(GraphAdapterError::InvalidEvent)?;
    request.path = format!("/me/todo/lists/{}/tasks", payload.list_id);
    request.body = payload.canonical_json().map_err(GraphAdapterError::InvalidEvent)?;
    request.integrity_hash = request_integrity_hash(&request);
    Ok(request)
}

/// Concrete orchestration boundary for Microsoft Graph.
pub struct MicrosoftGraphExecutionAdapter<T> { transport: T }

impl<T: GraphTransport> MicrosoftGraphExecutionAdapter<T> {
    /// Executes a signed request with a first-class revocation control.
    ///
    /// REVOKE is checked after signature verification and again immediately
    /// before transport. A valid signature can never bypass a later
    /// revocation. Revocation also clears scheduled retries.
    pub fn execute_signed_with_control(
        &mut self,
        event: &EventEnvelope,
        signed: &signature::GraphRequestSignature,
        public_key: &[u8; 32],
        registry: &mut IdempotencyRegistry,
        control: &ExecutionControl,
    ) -> Result<GraphExecutionReceipt, GraphAdapterError> {
        let authorization_reference = event.authorization.reference.as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or(GraphAdapterError::AuthorizationReferenceMissing)?;
        let request = build_request(event, authorization_reference)?;
        signature::verify_request_signature(&request, signed, public_key)
            .map_err(|error| GraphAdapterError::InvalidEvent(format!("signature verification failed: {error:?}")))?;
        revocation_check(control).map_err(map_safety_error)?;
        let claim = pre_side_effect_check(event, registry).map_err(map_safety_error)?;
        if !matches!(claim, ClaimDecision::Claimed) { return Err(GraphAdapterError::DuplicateIdempotencyKey); }
        revocation_check(control).map_err(map_safety_error)?;
        let result = self.transport.send(&request)?;
        if !(200..300).contains(&result.status_code) { return Err(GraphAdapterError::GraphRejected(result.status_code)); }
        Ok(GraphExecutionReceipt {
            event_id: event.event_id.clone(), trace_id: event.trace_id.clone(),
            authorization_reference: authorization_reference.to_string(),
            idempotency_key: event.idempotency_key.clone(), status_code: result.status_code,
            external_reference: result.external_reference,
        })
    }
    /// Executes only after the request signature and cryptographic provenance
    /// have been verified immediately before the side-effect boundary.
    ///
    /// This gate does not create authorization. It consumes an already
    /// authorized execution and re-checks authorization, integrity,
    /// signature, provenance and idempotency before transport.
    pub fn execute_signed(
        &mut self,
        event: &EventEnvelope,
        signed: &signature::GraphRequestSignature,
        public_key: &[u8; 32],
        registry: &mut IdempotencyRegistry,
    ) -> Result<GraphExecutionReceipt, GraphAdapterError> {
        let authorization_reference = event.authorization.reference.as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or(GraphAdapterError::AuthorizationReferenceMissing)?;

        let request = build_request(event, authorization_reference)?;
        signature::verify_request_signature(&request, signed, public_key)
            .map_err(|error| GraphAdapterError::InvalidEvent(format!("signature verification failed: {error:?}")))?;

        let claim = pre_side_effect_check(event, registry).map_err(map_safety_error)?;
        if !matches!(claim, ClaimDecision::Claimed) {
            return Err(GraphAdapterError::DuplicateIdempotencyKey);
        }

        let result = self.transport.send(&request)?;
        if !(200..300).contains(&result.status_code) {
            return Err(GraphAdapterError::GraphRejected(result.status_code));
        }

        Ok(GraphExecutionReceipt {
            event_id: event.event_id.clone(),
            trace_id: event.trace_id.clone(),
            authorization_reference: authorization_reference.to_string(),
            idempotency_key: event.idempotency_key.clone(),
            status_code: result.status_code,
            external_reference: result.external_reference,
        })
    }
}

impl<T> MicrosoftGraphExecutionAdapter<T> {
    /// Creates an adapter around an explicit Graph transport.
    pub fn new(transport: T) -> Self { Self { transport } }
}

impl<T: GraphTransport> MicrosoftGraphExecutionAdapter<T> {
    /// Executes one operation after PALACO checks and idempotency claim pass.
    pub fn execute(&mut self, event: &EventEnvelope, registry: &mut IdempotencyRegistry) -> Result<GraphExecutionReceipt, GraphAdapterError> {
        let authorization_reference = event.authorization.reference.as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or(GraphAdapterError::AuthorizationReferenceMissing)?;
        let request = build_request(event, authorization_reference)?;
        if !verify_request_integrity(&request) { return Err(GraphAdapterError::InvalidEvent("request integrity mismatch".into())); }
        let claim = pre_side_effect_check(event, registry).map_err(map_safety_error)?;
        if !matches!(claim, ClaimDecision::Claimed) { return Err(GraphAdapterError::DuplicateIdempotencyKey); }
        let result = self.transport.send(&request)?;
        if !(200..300).contains(&result.status_code) { return Err(GraphAdapterError::GraphRejected(result.status_code)); }
        Ok(GraphExecutionReceipt {
            event_id: event.event_id.clone(),
            trace_id: event.trace_id.clone(),
            authorization_reference: authorization_reference.to_string(),
            idempotency_key: event.idempotency_key.clone(),
            status_code: result.status_code,
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
        SafetyError::RevokedExecution => GraphAdapterError::RevokedExecution,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use palaco_office_event_contract::{Authorization, ProposedAction};

    struct RecordingTransport { status_code: u16 }
    impl GraphTransport for RecordingTransport {
        fn send(&self, _request: &GraphRequest) -> Result<GraphTransportResult, GraphAdapterError> {
            Ok(GraphTransportResult { status_code: self.status_code, external_reference: Some("graph-object-024".into()) })
        }
    }

    fn event() -> EventEnvelope {
        EventEnvelope {
            event_id: "event-024".into(),
            authorization: Authorization { state: AuthorizationState::Granted, reference: Some("auth-024".into()) },
            execution: ExecutionState::Started,
            trace_id: "trace-024".into(),
            idempotency_key: "idem-024".into(),
            proposed_action: Some(ProposedAction { action_type: "create_task".into(), destination: "todo".into() }),
            evidence_ref: "evidence-024".into(),
            source_ref: "graph:message-024".into(),
        }
    }

    #[test]
    fn request_integrity_is_self_verifying() -> Result<(), GraphAdapterError> {
        let request = build_request(&event(), "auth-024")?;
        assert!(verify_request_integrity(&request));
        assert_eq!(request.source_ref, "graph:message-024");
        Ok(())
    }

    #[test]
    fn changed_request_fails_integrity_verification() -> Result<(), GraphAdapterError> {
        let mut request = build_request(&event(), "auth-024")?;
        request.body = "{\"tampered\":true}".into();
        assert!(!verify_request_integrity(&request));
        Ok(())
    }

    #[test]
    fn canonical_task_request_contains_explicit_binding() -> Result<(), GraphAdapterError> {
        let payload = palaco_office_event_contract::TaskCreatePayload {
            list_id: "list-027".into(),
            title: "PALACO".into(),
            body: Some("GO-027".into()),
        };
        let request = build_task_request(&event(), "auth-024", &payload)?;
        assert_eq!(request.path, "/me/todo/lists/list-027/tasks");
        assert!(request.body.contains("list-027"));
        assert!(verify_request_integrity(&request));
        Ok(())
    }

    #[test]
    fn rejected_graph_response_is_not_receipted_as_success() {
        let mut registry = IdempotencyRegistry::default();
        let mut adapter = MicrosoftGraphExecutionAdapter::new(RecordingTransport { status_code: 403 });
        assert_eq!(adapter.execute(&event(), &mut registry), Err(GraphAdapterError::GraphRejected(403)));
    }

    #[test]
    fn signed_execution_is_blocked_by_late_revocation() -> Result<(), GraphAdapterError> {
        let mut registry = IdempotencyRegistry::default();
        let mut adapter = MicrosoftGraphExecutionAdapter::new(RecordingTransport { status_code: 201 });
        let request = build_request(&event(), "auth-024")?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]);
        let signed = signature::sign_request(&request, "key-030", &key).map_err(|error| GraphAdapterError::InvalidEvent(format!("{error:?}")))?;
        let mut control = ExecutionControl::new("exec-030", "trace-024");
        control.revoke();
        assert_eq!(adapter.execute_signed_with_control(&event(), &signed, key.verifying_key().as_bytes(), &mut registry, &control), Err(GraphAdapterError::ExecutionTerminal));
        Ok(())
    }
    #[test]
    fn signed_execution_commit_gate_verifies_before_transport() -> Result<(), GraphAdapterError> {
        let mut registry = IdempotencyRegistry::default();
        let mut adapter = MicrosoftGraphExecutionAdapter::new(RecordingTransport { status_code: 201 });
        let request = build_request(&event(), "auth-024")?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]);
        let signed = signature::sign_request(&request, "key-029", &key)
            .map_err(|error| GraphAdapterError::InvalidEvent(format!("{error:?}")))?;
        let receipt = adapter.execute_signed(
            &event(),
            &signed,
            key.verifying_key().as_bytes(),
            &mut registry,
        )?;
        assert_eq!(receipt.status_code, 201);
        Ok(())
    }

    #[test]
    fn signed_execution_commit_gate_blocks_tampering() -> Result<(), GraphAdapterError> {
        let mut registry = IdempotencyRegistry::default();
        let mut adapter = MicrosoftGraphExecutionAdapter::new(RecordingTransport { status_code: 201 });
        let mut event = event();
        event.event_id = "tampered-event".into();
        let original = build_request(&event(), "auth-024")?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]);
        let signed = signature::sign_request(&original, "key-029", &key)
            .map_err(|error| GraphAdapterError::InvalidEvent(format!("{error:?}")))?;
        assert!(adapter.execute_signed(
            &event,
            &signed,
            key.verifying_key().as_bytes(),
            &mut registry,
        ).is_err());
        Ok(())
    }

    #[test]
    fn successful_response_preserves_lineage() -> Result<(), GraphAdapterError> {
        let mut registry = IdempotencyRegistry::default();
        let mut adapter = MicrosoftGraphExecutionAdapter::new(RecordingTransport { status_code: 201 });
        let receipt = adapter.execute(&event(), &mut registry)?;
        assert_eq!(receipt.event_id, "event-024");
        assert_eq!(receipt.trace_id, "trace-024");
        assert_eq!(receipt.authorization_reference, "auth-024");
        assert_eq!(receipt.status_code, 201);
        Ok(())
    }
}
