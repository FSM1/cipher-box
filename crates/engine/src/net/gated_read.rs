//! The gated fan-out read: the below-floor rule of ADR 0071 D1, stated once
//! for every read route.

use crate::gate::RejectionReason;

/// What a record strictly below its sequence floor reads as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BelowFloor {
    /// An endpoint failed and can hold a newer record (ADR 0071 D1).
    Unavailable,
    /// Every endpoint answered, so the record is a rollback (ADR 0071 D4).
    Rollback,
}

impl BelowFloor {
    /// The verdict on a record already known to be below the floor.
    pub(crate) fn after_fanout(endpoint_failed: bool) -> Self {
        if endpoint_failed {
            Self::Unavailable
        } else {
            Self::Rollback
        }
    }
}

/// The verdict on `sequence` against `floor`; `None` at or above the floor.
pub(crate) fn below_floor(sequence: u64, floor: u64, endpoint_failed: bool) -> Option<BelowFloor> {
    (sequence < floor).then(|| BelowFloor::after_fanout(endpoint_failed))
}

/// The verdict on a gate refusal; `None` for a refusal that is not the
/// sequence stage's below-floor refusal.
pub(crate) fn sequence_refusal(
    reason: &RejectionReason,
    endpoint_failed: bool,
) -> Option<BelowFloor> {
    match reason {
        RejectionReason::SequenceNotNewer { floor, sequence } => {
            below_floor(*sequence, *floor, endpoint_failed)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sequence_below_the_floor_is_unavailable_only_while_an_endpoint_fails() {
        for (sequence, endpoint_failed, expected) in [
            (4, true, Some(BelowFloor::Unavailable)),
            (4, false, Some(BelowFloor::Rollback)),
            (5, true, None),
            (5, false, None),
            (6, true, None),
            (6, false, None),
        ] {
            assert_eq!(
                below_floor(sequence, 5, endpoint_failed),
                expected,
                "sequence {sequence}, endpoint failed {endpoint_failed}"
            );
            assert_eq!(
                sequence_refusal(
                    &RejectionReason::SequenceNotNewer { floor: 5, sequence },
                    endpoint_failed
                ),
                expected,
                "sequence {sequence}, endpoint failed {endpoint_failed}"
            );
        }
    }

    #[test]
    fn a_refusal_off_the_sequence_stage_is_no_below_floor_verdict() {
        let reason = RejectionReason::EpochBelowFloor { floor: 5, epoch: 4 };
        assert_eq!(sequence_refusal(&reason, true), None);
        assert_eq!(sequence_refusal(&reason, false), None);
    }
}
