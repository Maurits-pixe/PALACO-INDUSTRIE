#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// The seven constitutional seats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AmbassadorSeat {
    /// The Architect's seat.
    Architect,
    /// Ambassador seat two.
    Ambassador2,
    /// Ambassador seat three.
    Ambassador3,
    /// Ambassador seat four.
    Ambassador4,
    /// Ambassador seat five.
    Ambassador5,
    /// Ambassador seat six.
    Ambassador6,
    /// Ambassador seat seven.
    Ambassador7,
}

/// A recorded Council decision by one seat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Vote {
    /// Consent.
    Approve,
    /// Non-consent.
    Reject,
    /// A valid blocking veto.
    Veto,
}

/// One attributable Council vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbassadorDecision {
    /// Seat that produced the decision.
    pub seat: AmbassadorSeat,
    /// Decision made by that seat.
    pub vote: Vote,
    /// Stable provenance reference for the decision.
    pub provenance_ref: String,
    /// Time-bound scope reference.
    pub scope_ref: String,
}

/// Result of evaluating the Council's consent threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDecision {
    /// Fewer than five approvals and no veto: not yet consented.
    Pending,
    /// Five or more approvals and fewer than seven approvals.
    FirstConsent,
    /// All seven seats approve.
    FinalGrant,
    /// A valid veto blocks the decision.
    BlockedByVeto,
}

/// Evaluates seven individually attributable decisions.
///
/// This function models governance consent only. It never grants execution
/// authority and never changes an Office event's authorization state.
pub fn evaluate_consent(decisions: &[AmbassadorDecision]) -> Result<ConsentDecision, String> {
    if decisions.len() != 7 {
        return Err("Council of Seven requires exactly seven decisions".into());
    }

    let mut approvals = 0usize;
    let mut veto = false;
    for decision in decisions {
        if decision.provenance_ref.trim().is_empty() {
            return Err("every Council decision requires provenance".into());
        }
        if decision.scope_ref.trim().is_empty() {
            return Err("every Council decision requires scope".into());
        }
        match decision.vote {
            Vote::Approve => approvals += 1,
            Vote::Veto => veto = true,
            Vote::Reject => {}
        }
    }

    if veto {
        return Ok(ConsentDecision::BlockedByVeto);
    }
    if approvals == 7 {
        return Ok(ConsentDecision::FinalGrant);
    }
    if approvals >= 5 {
        return Ok(ConsentDecision::FirstConsent);
    }
    Ok(ConsentDecision::Pending)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decisions(vote: Vote) -> Vec<AmbassadorDecision> {
        [
            AmbassadorSeat::Architect,
            AmbassadorSeat::Ambassador2,
            AmbassadorSeat::Ambassador3,
            AmbassadorSeat::Ambassador4,
            AmbassadorSeat::Ambassador5,
            AmbassadorSeat::Ambassador6,
            AmbassadorSeat::Ambassador7,
        ]
        .into_iter()
        .map(|seat| AmbassadorDecision {
            seat,
            vote: vote.clone(),
            provenance_ref: "proof:decision".into(),
            scope_ref: "scope:100y".into(),
        })
        .collect()
    }

    #[test]
    fn five_approvals_are_first_consent() {
        let mut values = decisions(Vote::Reject);
        for value in values.iter_mut().take(5) {
            value.vote = Vote::Approve;
        }
        assert_eq!(evaluate_consent(&values), Ok(ConsentDecision::FirstConsent));
    }

    #[test]
    fn seven_approvals_are_final_grant() {
        assert_eq!(evaluate_consent(&decisions(Vote::Approve)), Ok(ConsentDecision::FinalGrant));
    }

    #[test]
    fn veto_blocks_even_with_seven_votes() {
        let mut values = decisions(Vote::Approve);
        values[6].vote = Vote::Veto;
        assert_eq!(evaluate_consent(&values), Ok(ConsentDecision::BlockedByVeto));
    }
}
