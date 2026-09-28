//! Administrative reporting period and closing contract.

/// Lifecycle state of an administrative reporting period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeriodState {
    /// Period is open for ordinary administrative recording.
    Open,
    /// Period is under controlled closing verification.
    Closing,
    /// Period is closed against ordinary mutation.
    Closed,
    /// Period was reopened through an explicitly authorized process.
    Reopened,
}

/// A period-boundary record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdministrativePeriod {
    /// Stable period identifier.
    pub period_id: String,
    /// Inclusive period start.
    pub starts_at: String,
    /// Exclusive period end.
    pub ends_at: String,
    /// Current lifecycle state.
    pub state: PeriodState,
    /// Provenance reference for the period operation.
    pub provenance_ref: String,
}

impl AdministrativePeriod {
    /// Validate the minimum period identity and provenance.
    pub fn validate(&self) -> Result<(), PeriodError> {
        if self.period_id.trim().is_empty()
            || self.starts_at.trim().is_empty()
            || self.ends_at.trim().is_empty()
            || self.provenance_ref.trim().is_empty()
        {
            return Err(PeriodError::MissingRequiredField);
        }
        if self.starts_at >= self.ends_at {
            return Err(PeriodError::InvalidRange);
        }
        Ok(())
    }

    /// Whether ordinary ledger mutation is blocked by the period state.
    pub fn blocks_ordinary_mutation(&self) -> bool {
        matches!(self.state, PeriodState::Closed)
    }
}

/// Fail-closed period errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeriodError {
    /// Required period data is absent.
    MissingRequiredField,
    /// Start must precede end.
    InvalidRange,
}

/// Closing is a state transition, not deletion of historical evidence.
pub const CLOSING_RULE: &str = "CLOSING ≠ DELETION";
/// A closed period cannot be silently rewritten.
pub const CLOSED_RULE: &str = "CLOSED ≠ MUTABLE";
/// Reporting does not create execution authority.
pub const REPORTING_RULE: &str = "REPORTING ≠ AUTHORIZATION";
