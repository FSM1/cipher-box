//! One version's durable upload progress (blueprint/engine.md "Sync core: Ops").
//!
//! Without a mark, a leaf missing before the first present one is
//! indistinguishable from one a previous pass uploaded — so an evicted or
//! deleted prefix would publish a version whose manifest names blocks nothing
//! holds. The drain reads it to resume; staged-bytes hygiene reads it to decide
//! whether an abandoned version's leaves ever reached a destination.

use crate::settings::Destinations;

/// The staging-key prefix one version's upload progress is marked under.
///
/// **One key per version**, so a second content op cannot erase the first's
/// progress and a dead letter's verdict is still decidable against the version's
/// own mark long after another op has taken the queue head.
///
/// Kept short for [`RETIRE_LEDGER_PREFIX`]'s reason: the desktop store spells a
/// staging key as a hex filename, at twice its byte length.
///
/// [`RETIRE_LEDGER_PREFIX`]: crate::net::RETIRE_LEDGER_PREFIX
pub const UPLOAD_MARK_PREFIX: &[u8] = b"cbx/um/";

/// The key one version's upload mark lives at. The root CID is the key, so it is
/// not written into the value.
pub fn upload_mark_key(root_cid: &[u8]) -> Vec<u8> {
    let mut key = UPLOAD_MARK_PREFIX.to_vec();
    key.extend_from_slice(root_cid);
    key
}

/// The mark's wire form: the destinations the progress was made towards, then a
/// big-endian `u32` leaf count. `None` where the count is not one this version
/// could have reached — AGENTS.md rule 8's release-active mirror of
/// [`read_mark`]'s bound, so a mark the reader discards can never be written.
/// The reader's other bound is on the destination shape, which
/// [`Destinations`] enforces at its own constructors.
pub fn encode_upload_mark(
    destinations: &Destinations,
    count: usize,
    leaves: usize,
) -> Option<Vec<u8>> {
    let claim = u32::try_from(count).ok().filter(|_| count <= leaves)?;
    let mut mark = destinations.encode().to_vec();
    mark.extend_from_slice(&claim.to_be_bytes());
    Some(mark)
}

/// The destinations a stored mark was made towards and the leaves it claims
/// reached them, or `None` for a torn mark, a count no `leaves`-leaf version
/// could have reached, or bytes this build did not write.
fn read_mark(stored: &[u8], leaves: usize) -> Option<(Destinations, usize)> {
    let (named, count) = stored.split_at_checked(Destinations::LEN)?;
    let count = u32::from_be_bytes(<[u8; 4]>::try_from(count).ok()?) as usize;
    Destinations::decode(named)
        .filter(|_| count <= leaves)
        .map(|earlier| (earlier, count))
}

/// Leaves of a `leaves`-leaf version the stored mark claims left staging for a
/// destination. **`None` is "unknown", never "none"**: a mark that is absent or
/// unreadable is no evidence that the bytes were never handed off, and the one
/// caller that acts on this destroys the version's only content-key carrier.
///
/// Says nothing about *which* destination — that is [`resume_from`]'s question.
pub(crate) fn marked_leaves(stored: &[u8], leaves: usize) -> Option<usize> {
    read_mark(stored, leaves).map(|(_, count)| count)
}

/// What a stored upload mark says about resuming this version at `here`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Resume {
    /// Leaves already released from staging that the leg which can fail this op
    /// holds, so their absence is progress rather than loss.
    pub(crate) uploaded: usize,
    /// Leaves a dual write's mirror will never hold, because they were released
    /// to a provider these destinations do not name.
    pub(crate) mirror_gap: bool,
}

/// Read the stored mark against the destinations this pass must reach.
///
/// A mark whose destinations do not include the leg that can fail this op covers
/// nothing: those leaves were released to somewhere else, and no absence is
/// excused by bytes this leg never received. A mirror the mark leaves short is
/// reported, not fatal — a dual write's external leg never fails the op.
pub(crate) fn resume_from(stored: &[u8], here: &Destinations, leaves: usize) -> Resume {
    let Some((earlier, uploaded)) = read_mark(stored, leaves).filter(|(_, count)| *count > 0)
    else {
        return Resume::default();
    };
    match here.required_legs_hold(&earlier) {
        true => Resume {
            uploaded,
            mirror_gap: !here.mirror_leg_holds(&earlier),
        },
        false => Resume::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::ByoIpfsConfig;
    use crate::settings::Placement;

    const ROOT: &[u8] = b"root-cid";

    fn byo(endpoint: &str) -> ByoIpfsConfig {
        ByoIpfsConfig {
            endpoint: endpoint.to_owned(),
            kind: crate::content::ByoKind::Kubo,
            access_token: None,
        }
    }

    /// AGENTS.md rule 8 for the upload mark: one bound, both directions. The
    /// encode guard returns `None` in every build rather than asserting, and the
    /// reader reaches the same verdict on bytes planted past it.
    #[test]
    fn a_mark_claiming_more_leaves_than_the_version_has_is_refused_on_both_sides() {
        let here = Placement::Hosted.destinations();
        let planted = |count: u32| {
            let mut mark = here.encode().to_vec();
            mark.extend_from_slice(&count.to_be_bytes());
            mark
        };
        for count in [4usize, 5, usize::try_from(u32::MAX).expect("64-bit")] {
            assert!(
                encode_upload_mark(&here, count, 3).is_none(),
                "{count}: the writer refuses what the reader discards",
            );
            let planted = planted(u32::try_from(count).unwrap_or(u32::MAX));
            assert_eq!(
                marked_leaves(&planted, 3),
                None,
                "{count}: a corrupt mark is no evidence about any leaf",
            );
            assert_eq!(resume_from(&planted, &here, 3), Resume::default());
        }
        // The in-range case still round-trips, so the bound is the only change.
        let mark = encode_upload_mark(&here, 2, 3).expect("in range");
        assert_eq!(marked_leaves(&mark, 3), Some(2));
        assert_eq!(
            resume_from(&mark, &here, 3),
            Resume {
                uploaded: 2,
                mirror_gap: false
            },
        );
    }

    /// One key per version, so a second content op's progress lands beside the
    /// first's rather than over it.
    #[test]
    fn each_version_marks_its_progress_under_its_own_key() {
        assert_ne!(upload_mark_key(ROOT), upload_mark_key(b"another-root"));
        assert!(upload_mark_key(ROOT).starts_with(UPLOAD_MARK_PREFIX));
    }

    /// A leaf released from staging is excused only where the leg that can fail
    /// this op already holds it. Turning the mirror on or off leaves the hosted
    /// store holding everything it held, so the version resumes; moving the leg
    /// that must hold the bytes leaves the mark covering nothing, and the hole
    /// guard reports the loss it is.
    #[test]
    fn a_resumed_mark_covers_only_what_the_op_failing_leg_already_holds() {
        let one = Placement::Dual(byo("https://one.example"));
        let two = Placement::Dual(byo("https://two.example"));
        let external = Placement::External(byo("https://one.example"));
        let full = Resume {
            uploaded: 2,
            mirror_gap: false,
        };
        let gapped = Resume {
            uploaded: 2,
            mirror_gap: true,
        };

        let resume = |here: &Placement, earlier: &Placement| {
            let mark = encode_upload_mark(&earlier.destinations(), 2, 3).expect("in range");
            resume_from(&mark, &here.destinations(), 3)
        };

        assert_eq!(resume(&Placement::Hosted, &one), full);
        assert_eq!(resume(&one, &one), full);
        assert_eq!(resume(&external, &one), full);
        assert_eq!(
            resume(&one, &Placement::Hosted),
            gapped,
            "the hosted store holds them; only the new mirror does not"
        );
        assert_eq!(resume(&one, &two), gapped);
        assert_eq!(
            resume(&external, &two),
            Resume::default(),
            "external-only publishes from the provider that never took them"
        );
        assert_eq!(resume(&external, &Placement::Hosted), Resume::default());
        assert_eq!(resume(&Placement::Hosted, &external), Resume::default());
    }

    /// A mark claiming nothing releases nothing, so a placement change over it
    /// is not a gap to report — but it is still a mark, and still says the
    /// version has handed off no leaf.
    #[test]
    fn an_empty_mark_gaps_no_mirror_and_still_answers() {
        let mark = encode_upload_mark(&Placement::Hosted.destinations(), 0, 3).expect("in range");
        assert_eq!(
            resume_from(
                &mark,
                &Placement::Dual(byo("https://one.example")).destinations(),
                3
            ),
            Resume::default(),
        );
        assert_eq!(marked_leaves(&mark, 3), Some(0));
    }

    /// The mark's destination prefix is read fail-closed: bytes no encode could
    /// have produced excuse no absent leaf, and say nothing about one either.
    #[test]
    fn a_mark_opening_on_unencodable_destinations_covers_nothing() {
        let here = Placement::Hosted.destinations();
        let mut mark = encode_upload_mark(&here, 2, 3).expect("in range");
        mark[0] = 3;
        assert_eq!(marked_leaves(&mark, 3), None);
        assert_eq!(resume_from(&mark, &here, 3), Resume::default());
    }

    /// A version with no leaves at all — an empty file — has no leaf to be
    /// missing, so no mark is needed to say so.
    #[test]
    fn an_empty_version_reads_a_zero_claim() {
        let here = Placement::Hosted.destinations();
        let mark = encode_upload_mark(&here, 0, 0).expect("in range");
        assert_eq!(marked_leaves(&mark, 0), Some(0));
        assert!(encode_upload_mark(&here, 1, 0).is_none());
    }
}
