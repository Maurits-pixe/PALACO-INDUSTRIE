#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Constitutional foundation for PALACO's future Administration Engine.
//!
//! This crate models administrative facts and their provenance. It deliberately
//! does not authorize, execute, or settle financial actions.

pub mod atomic_close;
pub mod closing_gate;
pub mod period;
pub mod reconciliation;

/// Constitutional distinction between an administrative fact and an action.
pub const ADMINISTRATION_RULE: &str = "ADMINISTRATIVE FACT ≠ AUTHORITY";

/// Separation between recording and execution.
pub const RECORD_RULE: &str = "RECORD ≠ EXECUTION";

/// Administrative facts must remain attributable and traceable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdministrativeFact {
    /// Stable administrative record identifier.
    pub record_id: String,
    /// PALACO identity responsible for the record.
    pub identity_ref: String,
    /// Provenance reference.
    pub provenance_ref: String,
    /// Classification of the administrative fact.
    pub fact_type: String,
    /// Canonical source reference.
    pub source_ref: String,
}

impl AdministrativeFact {
    /// Validate the minimum constitutional identity and provenance boundary.
    pub fn validate(&self) -> Result<(), AdministrationError> {
        if self.record_id.trim().is_empty()
            || self.identity_ref.trim().is_empty()
            || self.provenance_ref.trim().is_empty()
            || self.fact_type.trim().is_empty()
            || self.source_ref.trim().is_empty()
        {
            return Err(AdministrationError::MissingRequiredField);
        }
        Ok(())
    }
}

/// Fail-closed Administration Engine errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdministrationError {
    /// A required constitutional field was absent.
    MissingRequiredField,
}

/// Financial and administrative action categories reserved for future layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdministrativeDomain {
    /// Invoices and receivables.
    Invoicing,
    /// Expenses and payables.
    Expenses,
    /// Contracts and obligations.
    Contracts,
    /// Assets and ownership records.
    Assets,
    /// Payroll records.
    Payroll,
    /// Tax and statutory records.
    Tax,
    /// Financial reporting.
    Reporting,
    /// Immutable audit/provenance records.
    Audit,
}
