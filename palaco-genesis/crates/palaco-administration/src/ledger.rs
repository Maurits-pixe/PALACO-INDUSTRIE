//! Append-only administrative ledger contract.

/// A signed/provenance-bound administrative ledger entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    /// Stable record identity.
    pub record_id: String,
    /// Entry sequence within the administrative stream.
    pub sequence: u64,
    /// Administrative fact type.
    pub fact_type: String,
    /// Amount in the smallest declared unit, when monetary.
    pub amount_minor: Option<i64>,
    /// Currency code, when monetary.
    pub currency: Option<String>,
    /// Provenance reference.
    pub provenance_ref: String,
}

impl LedgerEntry {
    /// Validate identity, sequence, and provenance.
    pub fn validate(&self) -> Result<(), LedgerError> {
        if self.record_id.trim().is_empty()
            || self.fact_type.trim().is_empty()
            || self.provenance_ref.trim().is_empty()
        {
            return Err(LedgerError::MissingRequiredField);
        }
        if self.sequence == 0 {
            return Err(LedgerError::InvalidSequence);
        }
        match (&self.amount_minor, &self.currency) {
            (Some(_), Some(code)) if !code.trim().is_empty() => Ok(()),
            (Some(_), _) => Err(LedgerError::MissingCurrency),
            (None, Some(_)) => Err(LedgerError::UnexpectedCurrency),
            (None, None) => Ok(()),
        }
    }
}

/// Fail-closed ledger errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerError {
    /// Required data is absent.
    MissingRequiredField,
    /// Sequence zero is reserved as an invalid/uninitialized value.
    InvalidSequence,
    /// Monetary amount requires a currency.
    MissingCurrency,
    /// Currency without an amount is not accepted.
    UnexpectedCurrency,
}
