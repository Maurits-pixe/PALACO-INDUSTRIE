//! Administrative reconciliation contract.

/// Result of comparing two evidence-bearing administrative records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationOutcome {
    /// Records agree on the reconciliation key and value.
    Matched,
    /// Records exist but materially differ.
    Mismatched,
    /// A required counterpart could not be found.
    Missing,
    /// The same reconciliation identity occurs more than once.
    Duplicate,
    /// Available evidence is insufficient to determine the state.
    Unknown,
}

/// A fail-closed reconciliation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationResult {
    /// Stable reconciliation identity.
    pub reconciliation_id: String,
    /// Administrative record being reconciled.
    pub record_id: String,
    /// Evidence/source reference used for comparison.
    pub source_ref: String,
    /// Observed outcome.
    pub outcome: ReconciliationOutcome,
}

impl ReconciliationResult {
    /// Validate the evidence identity.
    pub fn validate(&self) -> Result<(), ReconciliationError> {
        if self.reconciliation_id.trim().is_empty()
            || self.record_id.trim().is_empty()
            || self.source_ref.trim().is_empty()
        {
            return Err(ReconciliationError::MissingRequiredField);
        }
        Ok(())
    }

    /// Whether the result is safe to classify as reconciled.
    pub fn is_reconciled(&self) -> bool {
        matches!(self.outcome, ReconciliationOutcome::Matched)
    }
}

/// Fail-closed reconciliation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationError {
    /// Required evidence identity is absent.
    MissingRequiredField,
}

/// Reconciliation does not authorize a financial action.
pub const AUTHORITY_RULE: &str = "RECONCILIATION ≠ AUTHORIZATION";
/// A mismatch requires evidence/review rather than silent correction.
pub const MISMATCH_RULE: &str = "MISMATCH ≠ CORRECTION";
/// Unknown evidence cannot be promoted to a confirmed match.
pub const UNKNOWN_RULE: &str = "UNKNOWN ≠ MATCHED";
