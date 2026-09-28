#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Canonical execution-proof binding contract.

/// Immutable references required for an execution proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionProof {
    /// Execution identity.
    pub execution_id: String,
    /// Authorization reference.
    pub authorization_reference: String,
    /// Provenance reference.
    pub provenance_reference: String,
    /// SHA-256 digest of the exact canonical signed request.
    pub signed_request_sha256: String,
    /// Cryptographic signature reference.
    pub signature_reference: String,
}

/// Fail-closed proof validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// A required field is missing.
    MissingField,
    /// The signed request digest does not match.
    RequestDigestMismatch,
    /// The authorization reference does not match.
    AuthorizationMismatch,
    /// The provenance reference does not match.
    ProvenanceMismatch,
    /// The signature reference does not match.
    SignatureMismatch,
}

impl ExecutionProof {
    /// Validates that the proof is complete.
    pub fn validate(&self) -> Result<(), ProofError> {
        if self.execution_id.trim().is_empty()
            || self.authorization_reference.trim().is_empty()
            || self.provenance_reference.trim().is_empty()
            || self.signed_request_sha256.trim().is_empty()
            || self.signature_reference.trim().is_empty()
        {
            return Err(ProofError::MissingField);
        }
        Ok(())
    }

    /// Verifies the durable binding against exact request/signature facts.
    pub fn verify(
        &self,
        authorization_reference: &str,
        provenance_reference: &str,
        signed_request_sha256: &str,
        signature_reference: &str,
    ) -> Result<(), ProofError> {
        self.validate()?;
        if self.authorization_reference != authorization_reference {
            return Err(ProofError::AuthorizationMismatch);
        }
        if self.provenance_reference != provenance_reference {
            return Err(ProofError::ProvenanceMismatch);
        }
        if self.signed_request_sha256 != signed_request_sha256 {
            return Err(ProofError::RequestDigestMismatch);
        }
        if self.signature_reference != signature_reference {
            return Err(ProofError::SignatureMismatch);
        }
        Ok(())
    }
}

/// Canonical proof boundary.
pub const EXECUTION_PROOF_ORDER: &str =
    "EXECUTION_ID → AUTHORIZATION_REFERENCE → PROVENANCE_REFERENCE → SIGNED_REQUEST_SHA256 → SIGNATURE_REFERENCE";

/// Proof verification never grants authority.
pub const CONSTITUTIONAL_RULE: &str =
    "SIGNATURE + PROVENANCE + BINDING ≠ AUTHORIZATION";
