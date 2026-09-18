#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod task;

pub use task::TaskCreatePayload;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Authorization state for an Office automation event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorizationState { None, Requested, Granted, Rejected, Revoked, Expired }

/// Execution state independent from authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionState { NotStarted, Started, Completed, Failed, Blocked }

/// Minimal canonical event envelope shared by Office automation safety layers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Stable event identifier.
    pub event_id: String,
    /// Authorization state.
    pub authorization: Authorization,
    /// Execution state.
    pub execution: ExecutionState,
    /// Stable trace identifier.
    pub trace_id: String,
    /// Deterministic idempotency key.
    pub idempotency_key: String,
    /// Proposed external action, if any.
    pub proposed_action: Option<ProposedAction>,
    /// Evidence reference.
    pub evidence_ref: String,
    /// Source provenance reference.
    pub source_ref: String,
}

/// Authorization record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    /// Current authorization state.
    pub state: AuthorizationState,
    /// Explicit authorization reference.
    pub reference: Option<String>,
}

/// Proposed external operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedAction {
    /// Canonical action type.
    pub action_type: String,
    /// External destination.
    pub destination: String,
}

impl EventEnvelope {
    /// Validates mandatory constitutional evidence and identity fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.event_id.trim().is_empty() { return Err("event_id is required".into()); }
        if self.trace_id.trim().is_empty() { return Err("trace_id is required".into()); }
        if self.idempotency_key.trim().is_empty() { return Err("idempotency_key is required".into()); }
        if self.evidence_ref.trim().is_empty() { return Err("evidence_ref is required".into()); }
        if self.source_ref.trim().is_empty() { return Err("source_ref is required".into()); }
        Ok(())
    }
}

/// Deterministically derives an idempotency key from source/action identity.
pub fn idempotency_key(source_system: &str, source_object_id: &str, action_type: &str, destination: &str) -> String {
    let canonical = format!("{source_system}|{source_object_id}|{action_type}|{destination}");
    let digest = Sha256::digest(canonical.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
