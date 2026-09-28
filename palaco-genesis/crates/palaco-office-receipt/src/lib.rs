#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! External side-effect receipt and reconciliation contract.

/// Outcome observed at the external system boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalOutcome {
    /// The external system positively accepted the operation.
    Accepted,
    /// The external system explicitly rejected the operation.
    Rejected,
    /// No definitive response was observed.
    Unknown,
}

/// Durable receipt of an external operation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalReceipt {
    /// Execution identity.
    pub execution_id: String,
    /// Trace identity.
    pub trace_id: String,
    /// External system identifier.
    pub external_system: String,
    /// External reference, when supplied.
    pub external_reference: Option<String>,
    /// Observed outcome.
    pub outcome: ExternalOutcome,
    /// Request digest used at the side-effect boundary.
    pub signed_request_sha256: String,
}

/// Reconciliation state after an external operation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationState {
    /// External acceptance is recorded.
    Confirmed,
    /// External rejection is recorded.
    Rejected,
    /// The external state is not yet known.
    Pending,
}

/// Fail-closed receipt errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptError {
    /// Required identity/proof data is absent.
    MissingField,
    /// Accepted operations require an external reference.
    AcceptedWithoutReference,
}

impl ExternalReceipt {
    /// Validates the receipt at the external boundary.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.execution_id.trim().is_empty()
            || self.trace_id.trim().is_empty()
            || self.external_system.trim().is_empty()
            || self.signed_request_sha256.trim().is_empty()
        {
            return Err(ReceiptError::MissingField);
        }
        if matches!(self.outcome, ExternalOutcome::Accepted)
            && self.external_reference.as_deref().is_none_or(|value| value.is_empty())
        {
            return Err(ReceiptError::AcceptedWithoutReference);
        }
        Ok(())
    }

    /// Maps an observed external outcome to reconciliation state.
    pub fn reconciliation_state(&self) -> ReconciliationState {
        match self.outcome {
            ExternalOutcome::Accepted => ReconciliationState::Confirmed,
            ExternalOutcome::Rejected => ReconciliationState::Rejected,
            ExternalOutcome::Unknown => ReconciliationState::Pending,
        }
    }
}

/// An unknown result must never be treated as success.
pub const UNKNOWN_RULE: &str = "UNKNOWN ≠ SUCCESS";

/// Reconciliation never creates authorization.
pub const RECONCILIATION_RULE: &str = "RECONCILIATION ≠ AUTHORIZATION";
