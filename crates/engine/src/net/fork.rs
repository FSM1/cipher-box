//! The evidence of a same-sequence fork (ADR 0066, CONTEXT.md "Same-sequence
//! fork").

use cipherbox_core::ipns::{IpnsName, IpnsRecord, VerifiedRecord};

use super::eol::{self, EOL_RENEW_THRESHOLD};
use super::resolve::Adopter;
use crate::seams::UnixMillis;

/// A same-sequence fork one read met.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fork {
    /// The forked sequence.
    pub sequence: u64,
    /// An endpoint serves the other side: a gate-passing record of another
    /// value. A side only the cache holds is not served.
    pub served: bool,
}

/// The fork a read of `pick` met: a tie the gate passed (`served`), or a
/// cached copy at its sequence ([`cached_fork`]).
pub(crate) fn fork_of(pick: &VerifiedRecord, served: bool, cached: bool) -> Option<Fork> {
    (served || cached).then_some(Fork {
        sequence: pick.sequence,
        served,
    })
}

/// The tied records with a signed value other than `pick`'s. A tie of the
/// pick's own value changes no content, so it is no fork.
pub(crate) fn other_values<'t>(
    name: &'t IpnsName,
    pick: &'t VerifiedRecord,
    tied: &'t [Vec<u8>],
) -> impl Iterator<Item = &'t [u8]> {
    tied.iter()
        .map(Vec::as_slice)
        .filter(move |tie| verified(name, tie).is_some_and(|tie| tie.value != pick.value))
}

/// Whether one of `tied` passes `adopter`'s gate at the floor
/// ([`Adopter::gates_tie`]): a tie that does not is no fork evidence.
pub(crate) async fn served_fork<A: Adopter>(
    adopter: &A,
    name: &IpnsName,
    pick: &VerifiedRecord,
    tied: &[Vec<u8>],
) -> bool {
    for tie in other_values(name, pick, tied) {
        if adopter.gates_tie(name, tie).await {
            return true;
        }
    }
    false
}

/// Whether `cached` is another record at `pick`'s sequence with another signed
/// value.
pub(crate) fn cached_fork(name: &IpnsName, cached: Option<&[u8]>, pick: &VerifiedRecord) -> bool {
    cached
        .and_then(|cached| verified(name, cached))
        .is_some_and(|cached| cached.sequence == pick.sequence && cached.value != pick.value)
}

/// Whether `fork` holds back the renewal of a pick whose signed EOL is
/// `validity`: a served fork does while more than [`EOL_RENEW_THRESHOLD`] is
/// left, so the drain rebase or a re-PUT can heal it first. Inside the
/// threshold liveness wins, and the renewal buries the other side (ADR 0066
/// D3).
pub(crate) fn holds_renewal(fork: Option<Fork>, now: UnixMillis, validity: &[u8]) -> bool {
    fork.is_some_and(|fork| fork.served) && !eol::needs_renewal(now, validity, EOL_RENEW_THRESHOLD)
}

fn verified(name: &IpnsName, record_bytes: &[u8]) -> Option<VerifiedRecord> {
    IpnsRecord::unmarshal(record_bytes)
        .and_then(|record| record.verify(name))
        .ok()
}
