//! Owner entry — the owner seed cache and the seed cross-check (blueprint/
//! engine.md "Grants and ledger — Owner entry", #39 D6).
//!
//! In an owner session the canonical source of a scope's override seed is the
//! own-vault **owner seed cache** — the last-confirmed `{seed, epoch}` per
//! granted scope, refreshed on every confirmed owner read. The grantee-
//! maintained owner blob is only an accelerator. The trust rule is a cross-
//! check: the owner-blob seed, the ascent-link seed (when descending as an
//! ancestor), and the seed that actually unsealed the read-body must all agree.
//! Any disagreement is an **attributable abuse event** surfaced to the host —
//! never a silent failure — because a write-grantee that publishes a mismatched
//! owner blob or ascent link is caught here rather than trusted.
//!
//! Seeds are secret material in zeroizing owners; comparisons are constant-time
//! so a mismatch is never a timing oracle over a seed. This module holds no
//! crypto — it composes secret containers and equality only.

use std::collections::BTreeMap;

use cipherbox_core::suite::secret::SecretBytes;
use zeroize::Zeroizing;

use crate::secret_util::ct_eq_32;

/// The last-confirmed override seed and epoch for one scope — the canonical
/// owner-session view. `seed` is secret material; it zeroizes on drop.
#[derive(Clone)]
pub struct OwnerSeedEntry {
    seed: SecretBytes,
    /// The epoch the confirmed seed belongs to.
    pub epoch: u64,
}

impl OwnerSeedEntry {
    /// Borrow the confirmed override seed.
    pub fn seed(&self) -> &[u8; 32] {
        self.seed.as_bytes()
    }
}

/// The own-vault owner seed cache: canonical `{seed, epoch}` per granted scope,
/// keyed by scope id. Refreshed on every confirmed owner read (a passing
/// [`cross_check`]).
#[derive(Default)]
pub struct OwnerSeedCache {
    by_scope: BTreeMap<[u8; 16], OwnerSeedEntry>,
}

impl OwnerSeedCache {
    /// An empty cache — cold start adopts nothing until the first confirmed read.
    pub fn new() -> Self {
        Self::default()
    }

    /// The canonical entry for a scope, if one has been confirmed.
    pub fn get(&self, scope_id: &[u8; 16]) -> Option<&OwnerSeedEntry> {
        self.by_scope.get(scope_id)
    }

    /// Record a confirmed `{seed, epoch}` as canonical for a scope, replacing any
    /// prior entry (the confirmed read is authoritative).
    pub fn refresh(&mut self, scope_id: [u8; 16], seed: Zeroizing<[u8; 32]>, epoch: u64) {
        self.by_scope.insert(
            scope_id,
            OwnerSeedEntry {
                seed: SecretBytes::new(*seed),
                epoch,
            },
        );
    }
}

/// An attributable abuse event: a seed disagreement caught at owner entry. The
/// description is host-facing and carries no key material; it maps directly to
/// the facade's `AttributableAbuse` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbuseEvent {
    /// A stable, key-material-free description of the disagreement.
    pub description: String,
}

impl AbuseEvent {
    /// The stable classification name.
    pub fn check(&self) -> &'static str {
        "owner-seed-cross-check-disagreement"
    }
}

/// The outcome of an owner-entry cross-check.
pub enum OwnerEntry {
    /// All present seed sources agreed; the caller refreshes the cache with this
    /// canonical `{seed, epoch}`.
    Confirmed {
        /// The agreed override seed.
        seed: Zeroizing<[u8; 32]>,
        /// The epoch it belongs to.
        epoch: u64,
    },
    /// A disagreement — surfaced to the host, never silently dropped.
    Abuse(AbuseEvent),
}

/// Cross-check the owner-blob seed, the optional ascent-link seed, and the seed
/// that actually unsealed the read-body. All present sources must equal
/// `unseal_seed`; the first disagreement is an [`AbuseEvent`], otherwise the
/// agreed `{unseal_seed, epoch}` is [`OwnerEntry::Confirmed`] for the caller to
/// cache.
///
/// `unseal_seed` is the trusted anchor — it is the seed that demonstrably
/// derived the working read key at the gate — so the two accelerator sources are
/// checked against it, not against each other.
pub fn cross_check(
    owner_blob_seed: &[u8; 32],
    ascent_link_seed: Option<&[u8; 32]>,
    unseal_seed: &[u8; 32],
    epoch: u64,
) -> OwnerEntry {
    if !ct_eq_32(owner_blob_seed, unseal_seed) {
        return OwnerEntry::Abuse(AbuseEvent {
            description: "owner-blob seed disagrees with the unsealed scope seed".to_string(),
        });
    }
    if let Some(ascent) = ascent_link_seed {
        if !ct_eq_32(ascent, unseal_seed) {
            return OwnerEntry::Abuse(AbuseEvent {
                description: "ascent-link seed disagrees with the unsealed scope seed".to_string(),
            });
        }
    }
    OwnerEntry::Confirmed {
        seed: Zeroizing::new(*unseal_seed),
        epoch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x66; 32];
    const OTHER: [u8; 32] = [0x99; 32];
    const SCOPE: [u8; 16] = [0x44; 16];

    #[test]
    fn all_sources_agree_confirms_and_caches() {
        let outcome = cross_check(&SEED, Some(&SEED), &SEED, 4);
        let mut cache = OwnerSeedCache::new();
        match outcome {
            OwnerEntry::Confirmed { seed, epoch } => {
                assert!(ct_eq_32(&seed, &SEED), "seed mismatch");
                assert_eq!(epoch, 4);
                cache.refresh(SCOPE, seed, epoch);
            }
            OwnerEntry::Abuse(_) => panic!("agreement must confirm"),
        }
        assert!(
            ct_eq_32(cache.get(&SCOPE).unwrap().seed(), &SEED),
            "cached seed mismatch"
        );
        assert_eq!(cache.get(&SCOPE).unwrap().epoch, 4);
    }

    #[test]
    fn owner_blob_disagreement_is_attributable_abuse() {
        match cross_check(&OTHER, None, &SEED, 4) {
            OwnerEntry::Abuse(event) => {
                assert_eq!(event.check(), "owner-seed-cross-check-disagreement");
                assert!(event.description.contains("owner-blob"));
            }
            OwnerEntry::Confirmed { .. } => panic!("a disagreement must raise abuse"),
        }
    }

    #[test]
    fn ascent_link_disagreement_is_attributable_abuse() {
        match cross_check(&SEED, Some(&OTHER), &SEED, 4) {
            OwnerEntry::Abuse(event) => assert!(event.description.contains("ascent-link")),
            OwnerEntry::Confirmed { .. } => panic!("a disagreement must raise abuse"),
        }
    }

    #[test]
    fn no_ascent_link_still_cross_checks_the_owner_blob() {
        assert!(matches!(
            cross_check(&SEED, None, &SEED, 7),
            OwnerEntry::Confirmed { epoch: 7, .. }
        ));
    }

    #[test]
    fn refresh_replaces_the_prior_canonical_entry() {
        let mut cache = OwnerSeedCache::new();
        cache.refresh(SCOPE, Zeroizing::new(SEED), 1);
        cache.refresh(SCOPE, Zeroizing::new(OTHER), 2);
        assert!(
            ct_eq_32(cache.get(&SCOPE).unwrap().seed(), &OTHER),
            "cached seed mismatch"
        );
        assert_eq!(cache.get(&SCOPE).unwrap().epoch, 2);
    }
}
