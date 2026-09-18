#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Atomic execution proof commit contract.

/// Inputs required to cross the execution commit boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionCommitProof {
    /// Execution identity.
    pub execution_id: String,
    /// Authorization reference.
    pub authorization_reference: String,
    /// Provenance reference.
    pub provenance_reference: String,
    /// Exact canonical signed-request digest.
    pub signed_request_sha256: String,
    /// Cryptographic signature reference.
    pub signature_reference: String,
}

/// Fail-closed commit errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitError {
    /// Required proof material is absent.
    MissingProofMaterial,
    /// Authorization is not currently granted.
    AuthorizationNotGranted,
    /// Execution is not pending.
    ExecutionNotPending,
    /// Proof material conflicts with the durable record.
    ProofConflict,
}

impl ExecutionCommitProof {
    /// Validates proof material before the database boundary.
    pub fn validate(&self) -> Result<(), CommitError> {
        if self.execution_id.trim().is_empty()
            || self.authorization_reference.trim().is_empty()
            || self.provenance_reference.trim().is_empty()
            || self.signed_request_sha256.trim().is_empty()
            || self.signature_reference.trim().is_empty()
        {
            return Err(CommitError::MissingProofMaterial);
        }
        Ok(())
    }

    /// Requires the constitutional authorization state.
    pub fn require_granted(granted: bool) -> Result<(), CommitError> {
        if granted {
            Ok(())
        } else {
            Err(CommitError::AuthorizationNotGranted)
        }
    }

    /// Requires the execution to still be pending.
    pub fn require_pending(pending: bool) -> Result<(), CommitError> {
        if pending {
            Ok(())
        } else {
            Err(CommitError::ExecutionNotPending)
        }
    }
}

/// Canonical transaction order.
pub const COMMIT_ORDER: &str =
    "LOCK AUTHORIZATION → RE-READ → REQUIRE GRANTED → LOCK EXECUTION → REQUIRE PENDING → VERIFY PROOF → COMMIT";

/// The commit establishes durable state; it does not perform an external side effect.
pub const SIDE_EFFECT_RULE: &str =
    "COMMIT FIRST; EXTERNAL SIDE EFFECT SECOND";
