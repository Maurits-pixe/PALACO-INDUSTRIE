#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Durable execution-to-authorization binding contract.

/// A durable authorization binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationBinding {
    /// Execution identity.
    pub execution_id: String,
    /// Opaque authorization reference.
    pub authorization_reference: String,
    /// Durable authorization state.
    pub authorization_state: AuthorizationState,
    /// Provenance reference for the authorization fact.
    pub provenance_reference: String,
}

/// Durable authorization state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationState {
    /// Authorization was granted.
    Granted,
    /// Authorization was revoked.
    Revoked,
    /// Authorization expired.
    Expired,
}

impl AuthorizationBinding {
    /// Validates the binding without granting authority.
    pub fn validate(&self) -> Result<(), BindingError> {
        if self.execution_id.trim().is_empty() {
            return Err(BindingError::MissingExecutionId);
        }
        if self.authorization_reference.trim().is_empty() {
            return Err(BindingError::MissingAuthorizationReference);
        }
        if self.provenance_reference.trim().is_empty() {
            return Err(BindingError::MissingProvenance);
        }
        Ok(())
    }

    /// Returns whether the stored state permits the authorization boundary.
    pub fn permits_authorization(&self) -> bool {
        matches!(self.authorization_state, AuthorizationState::Granted)
    }
}

/// Fail-closed binding errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    /// Execution identity is absent.
    MissingExecutionId,
    /// Authorization reference is absent.
    MissingAuthorizationReference,
    /// Provenance is absent.
    MissingProvenance,
}

/// SQL contract for an atomic initial binding.
pub const BIND_SQL: &str =
    "BEGIN; LOCK current execution; REQUIRE GRANTED authorization; INSERT authorization binding; COMMIT;";

/// SQL contract for durable revocation propagation.
pub const REVOKE_SQL: &str =
    "BEGIN; LOCK authorization binding; SET authorization state REVOKED; COMMIT;";

/// SQL contract for durable expiration propagation.
pub const EXPIRE_SQL: &str =
    "BEGIN; LOCK authorization binding; SET authorization state EXPIRED; COMMIT;";
