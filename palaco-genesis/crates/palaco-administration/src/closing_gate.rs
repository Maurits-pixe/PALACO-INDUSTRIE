//! Evidence gate for closing an administrative reporting period.

/// Evidence required before a period may be closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosingEvidence {
    /// Period being closed.
    pub period_id: String,
    /// Provenance of the reconciliation snapshot.
    pub reconciliation_provenance: String,
    /// Provenance of the report.
    pub report_provenance: String,
    /// Number of unresolved mismatches.
    pub unresolved_mismatches: u64,
    /// Number of unresolved unknown observations.
    pub unresolved_unknowns: u64,
    /// Attributable closing decision reference.
    pub decision_ref: String,
}

impl ClosingEvidence {
    /// Validate the evidence required by the closing boundary.
    pub fn validate(&self) -> Result<(), ClosingGateError> {
        if self.period_id.trim().is_empty()
            || self.reconciliation_provenance.trim().is_empty()
            || self.report_provenance.trim().is_empty()
            || self.decision_ref.trim().is_empty()
        {
            return Err(ClosingGateError::MissingEvidence);
        }
        if self.unresolved_mismatches > 0 || self.unresolved_unknowns > 0 {
            return Err(ClosingGateError::UnresolvedEvidence);
        }
        Ok(())
    }
}

/// Fail-closed closing gate errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosingGateError {
    /// Required evidence or attribution is absent.
    MissingEvidence,
    /// Unresolved evidence prevents ordinary closing.
    UnresolvedEvidence,
}

/// A successful gate permits the state transition but does not itself execute it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosingGateReceipt {
    /// Period approved by the evidence gate.
    pub period_id: String,
    /// Decision that authorized the closing transition.
    pub decision_ref: String,
}

/// Closing evidence is not authorization and the gate is not execution.
pub const EVIDENCE_RULE: &str = "EVIDENCE ≠ AUTHORIZATION";
pub const GATE_RULE: &str = "GATE ≠ EXECUTION";
