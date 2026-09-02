//! Revocation classification — discovered, not delivered (blueprint/engine.md
//! "Grants and ledger", #25 D3/D4).
//!
//! Revocation is never a message; it is inferred from what a resolve finds. The
//! engine distinguishes three outcomes and surfaces the distinction to the host
//! (revoking is the owner's immediate-cut action, out of scope here — this slice
//! only classifies what is discovered):
//!
//! - **Revocation signal** — a fresh owner-signed record resolves, but there is
//!   no grant blob at your tag. That is the definitive "you were removed": the
//!   owner republished the committed set without you.
//! - **Unresolvable** — the name did not resolve to a fresh owner-signed record
//!   at all (unknown, superseded by a cut, or network-suppressed). Merely
//!   absent, never proof of revocation.
//! - **Epoch lag** — a fresh owner-signed record resolves and your tag is still
//!   committed, but its epoch is below your durable read-epoch floor: a
//!   sweep-pending staleness, not a revocation.

/// The three discovered outcomes plus the still-granted baseline. Only the three
/// non-`Granted` variants are surfaced as distinct host signals; `Granted` means
/// nothing changed.
///
/// A host renders one of these; it never computes one. Absence of a class is not
/// a class: a share no resolve has reached yet is "not yet known", and painting
/// that as `Granted` would show a revoked share as live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionClass {
    /// A fresh owner-signed record resolved and your blob is present — still
    /// granted, no revocation.
    Granted,
    /// A fresh owner-signed record with no blob at your tag — definitive
    /// revocation. The commitment covers each row, not the blob **set**, so any
    /// committed writer can strip a blob and produce this: sound to render,
    /// never sound to act on destructively.
    RevocationSignal,
    /// The name did not resolve to a fresh owner-signed record — unknown/stale,
    /// not a revocation.
    Unresolvable,
    /// A fresh owner-signed record whose epoch is below your durable read-epoch
    /// floor — sweep-pending staleness, not a revocation.
    EpochLag,
}

impl ResolutionClass {
    /// A stable, host-facing name (no key material).
    pub fn name(&self) -> &'static str {
        match self {
            ResolutionClass::Granted => "granted",
            ResolutionClass::RevocationSignal => "revocation-signal",
            ResolutionClass::Unresolvable => "unresolvable",
            ResolutionClass::EpochLag => "epoch-lag",
        }
    }
}

/// The observed facts a classification is a pure function of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolutionFacts {
    /// The name resolved to a record that passed both record-verify and
    /// commitment-verify against the contact-anchored owner identity — a *fresh
    /// owner-signed* record. `false` covers no record, a verify failure, a
    /// commitment for a different owner, and a set a cut superseded, which an
    /// owner really did sign but has withdrawn.
    pub owner_signed_record: bool,
    /// A grant blob is present at your self-located tag in that record.
    pub blob_present: bool,
    /// The record's epoch tag. A producer that unsealed the body has it
    /// AAD-confirmed; the `/shared` read reaches no unseal, so there it is the
    /// envelope's plaintext tag on a record already held to its name.
    pub record_epoch: u64,
    /// Your durable read-epoch floor for the scope.
    pub epoch_floor: u64,
}

impl ResolutionFacts {
    /// The facts a resolve that reached no fresh owner-signed record supports:
    /// absent, and absent is never a removal.
    pub fn unresolved(epoch_floor: u64) -> Self {
        Self {
            owner_signed_record: false,
            blob_present: false,
            record_epoch: 0,
            epoch_floor,
        }
    }
}

/// Classify a resolve outcome into the revocation triple (or `Granted`).
///
/// Order matters: absence of a fresh owner-signed record is *unresolvable*
/// first; then a missing blob at your tag on a present record is the definitive
/// *revocation signal* (it outranks an epoch check — a removed grant is a
/// removal regardless of epoch, and you could not unseal to confirm the epoch
/// anyway); an epoch behind your floor on a still-committed record is *epoch
/// lag*.
pub fn classify(facts: &ResolutionFacts) -> ResolutionClass {
    if !facts.owner_signed_record {
        return ResolutionClass::Unresolvable;
    }
    if !facts.blob_present {
        return ResolutionClass::RevocationSignal;
    }
    if facts.record_epoch < facts.epoch_floor {
        return ResolutionClass::EpochLag;
    }
    ResolutionClass::Granted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(owner_signed: bool, blob: bool, epoch: u64, floor: u64) -> ResolutionFacts {
        ResolutionFacts {
            owner_signed_record: owner_signed,
            blob_present: blob,
            record_epoch: epoch,
            epoch_floor: floor,
        }
    }

    #[test]
    fn fresh_owner_record_missing_blob_is_revocation_signal() {
        assert_eq!(
            classify(&facts(true, false, 3, 3)),
            ResolutionClass::RevocationSignal
        );
    }

    #[test]
    fn no_owner_signed_record_is_unresolvable() {
        assert_eq!(
            classify(&facts(false, false, 0, 0)),
            ResolutionClass::Unresolvable
        );
        // Even with a (stale) blob cached, absence of a fresh owner-signed record
        // is unresolvable, never revocation.
        assert_eq!(
            classify(&facts(false, true, 5, 1)),
            ResolutionClass::Unresolvable
        );
    }

    #[test]
    fn committed_but_below_floor_is_epoch_lag() {
        assert_eq!(
            classify(&facts(true, true, 2, 5)),
            ResolutionClass::EpochLag
        );
    }

    #[test]
    fn present_committed_at_floor_is_granted() {
        assert_eq!(classify(&facts(true, true, 5, 5)), ResolutionClass::Granted);
    }

    #[test]
    fn revocation_outranks_epoch_lag() {
        // No blob AND epoch behind floor: the removal is the signal, not lag.
        assert_eq!(
            classify(&facts(true, false, 1, 9)),
            ResolutionClass::RevocationSignal
        );
    }

    #[test]
    fn the_triple_names_are_stable() {
        assert_eq!(
            ResolutionClass::RevocationSignal.name(),
            "revocation-signal"
        );
        assert_eq!(ResolutionClass::Unresolvable.name(), "unresolvable");
        assert_eq!(ResolutionClass::EpochLag.name(), "epoch-lag");
    }
}
