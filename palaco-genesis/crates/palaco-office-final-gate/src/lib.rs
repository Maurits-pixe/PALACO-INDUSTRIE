#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Final pre-side-effect revocation and execution-proof gate.

/// Immutable facts presented to the final gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalGateInput {
    /// Execution identity.
    pub execution_id: String,
    /// Current authorization reference.
    pub authorization_reference: String,
    /// Current provenance reference.
    pub provenance_reference: String,
    /// Exact canonical signed-request digest.
    pub signed_request_sha256: String,
    /// Reference to the verified signature.
    pub signature_reference: String,
}

/// Fail-closed final-gate errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalGateError {
    /// A required field is absent.
    MissingField,
    /// Authorization is not granted at the final read.
    AuthorizationRevokedOrExpired,
    /// Execution is not in the executing state.
    ExecutionNotExecuting,
    /// Durable proof does not match.
    ProofMismatch,
}

/// Result of the final gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalGateReceipt {
    /// Execution identity that crossed the gate.
    pub execution_id: String,
    /// Digest of the exact signed request.
    pub signed_request_sha256: String,
}

impl FinalGateInput {
    /// Validates required proof material.
    pub fn validate(&self) -> Result<(), FinalGateError> {
        if self.execution_id.trim().is_empty()
            || self.authorization_reference.trim().is_empty()
            || self.provenance_reference.trim().is_empty()
            || self.signed_request_sha256.trim().is_empty()
            || self.signature_reference.trim().is_empty()
        {
            return Err(FinalGateError::MissingField);
        }
        Ok(())
    }

    /// Performs the final fail-closed state check.
    pub fn permit(
        &self,
        authorization_granted: bool,
        execution_executing: bool,
        proof_matches: bool,
    ) -> Result<FinalGateReceipt, FinalGateError> {
        self.validate()?;
        if !authorization_granted {
            return Err(FinalGateError::AuthorizationRevokedOrExpired);
        }
        if !execution_executing {
            return Err(FinalGateError::ExecutionNotExecuting);
        }
        if !proof_matches {
            return Err(FinalGateError::ProofMismatch);
        }
        Ok(FinalGateReceipt {
            execution_id: self.execution_id.clone(),
            signed_request_sha256: self.signed_request_sha256.clone(),
        })
    }
}

/// The final gate never performs the external side-effect.
pub const SIDE_EFFECT_BOUNDARY: &str =
    "FINAL GATE SUCCESS → EXTERNAL ADAPTER; FINAL GATE FAILURE → NO ACTION";

/// Revocation always has precedence over execution.
pub const REVOCATION_RULE: &str =
    "REVOKE → BLOCK PENDING/NEW EXECUTION → PRESERVE PROVENANCE";
