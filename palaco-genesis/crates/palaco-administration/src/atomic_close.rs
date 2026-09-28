//! Atomic PostgreSQL transaction for administrative period closing.

use postgres::{Client, Error as PostgresError};

use crate::closing_gate::{ClosingEvidence, ClosingGateError, ClosingGateReceipt};

/// Fail-closed errors produced by the atomic period-close boundary.
#[derive(Debug)]
pub enum PeriodCloseError {
    /// Database operation failed.
    Database(PostgresError),
    /// The requested period does not exist.
    PeriodNotFound,
    /// The period is already closed.
    AlreadyClosed,
    /// The period is not in a closable state.
    InvalidState,
    /// Submitted evidence does not match the durable reconciliation snapshot.
    EvidenceStale,
    /// Durable reconciliation evidence contains unresolved observations.
    UnresolvedEvidence,
    /// Required closing evidence is missing.
    InvalidEvidence(ClosingGateError),
}

impl From<PostgresError> for PeriodCloseError {
    fn from(error: PostgresError) -> Self {
        Self::Database(error)
    }
}

/// Atomically persist the closing gate and transition a period to CLOSED.
///
/// The operation performs:
/// LOCK → RE-READ → VERIFY → PERSIST GATE → CLOSE → COMMIT.
///
/// No ledger mutation or external side effect is performed.
pub fn close_period(
    client: &mut Client,
    evidence: &ClosingEvidence,
) -> Result<ClosingGateReceipt, PeriodCloseError> {
    evidence
        .validate()
        .map_err(PeriodCloseError::InvalidEvidence)?;

    let mut transaction = client.transaction()?;

    let period_state = transaction
        .query_opt(
            "SELECT state
             FROM palaco_administrative_period
             WHERE period_id = $1
             FOR UPDATE",
            &[&evidence.period_id],
        )?
        .ok_or(PeriodCloseError::PeriodNotFound)?;

    let state: String = period_state.get(0);

    if state == "CLOSED" {
        return Err(PeriodCloseError::AlreadyClosed);
    }

    if state != "OPEN" && state != "CLOSING" {
        return Err(PeriodCloseError::InvalidState);
    }

    let counts = transaction.query_one(
        "SELECT
             COUNT(*) FILTER (WHERE outcome = 'MISMATCHED')::BIGINT,
             COUNT(*) FILTER (WHERE outcome = 'UNKNOWN')::BIGINT
         FROM palaco_administrative_reconciliation
         WHERE period_id = $1",
        &[&evidence.period_id],
    )?;

    let unresolved_mismatches: i64 = counts.get(0);
    let unresolved_unknowns: i64 = counts.get(1);

    if unresolved_mismatches < 0
        || unresolved_unknowns < 0
        || evidence.unresolved_mismatches != unresolved_mismatches as u64
        || evidence.unresolved_unknowns != unresolved_unknowns as u64
    {
        return Err(PeriodCloseError::EvidenceStale);
    }

    if unresolved_mismatches != 0 || unresolved_unknowns != 0 {
        return Err(PeriodCloseError::UnresolvedEvidence);
    }

    transaction.execute(
        "INSERT INTO palaco_administrative_closing_gate
             (period_id, reconciliation_provenance, report_provenance,
              unresolved_mismatches, unresolved_unknowns, decision_ref, checked_at)
         VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
         ON CONFLICT (period_id) DO UPDATE
         SET reconciliation_provenance = EXCLUDED.reconciliation_provenance,
             report_provenance = EXCLUDED.report_provenance,
             unresolved_mismatches = EXCLUDED.unresolved_mismatches,
             unresolved_unknowns = EXCLUDED.unresolved_unknowns,
             decision_ref = EXCLUDED.decision_ref,
             checked_at = EXCLUDED.checked_at",
        &[
            &evidence.period_id,
            &evidence.reconciliation_provenance,
            &evidence.report_provenance,
            &(unresolved_mismatches as i64),
            &(unresolved_unknowns as i64),
            &evidence.decision_ref,
        ],
    )?;

    let updated = transaction.execute(
        "UPDATE palaco_administrative_period
         SET state = 'CLOSED', changed_at = CURRENT_TIMESTAMP
         WHERE period_id = $1
           AND state IN ('OPEN', 'CLOSING')",
        &[&evidence.period_id],
    )?;

    if updated != 1 {
        return Err(PeriodCloseError::InvalidState);
    }

    transaction.commit()?;

    Ok(ClosingGateReceipt {
        period_id: evidence.period_id.clone(),
        decision_ref: evidence.decision_ref.clone(),
    })
}
