//! The host-adapter trait — one implementation per mount technology
//! (blueprint/desktop.md "The FS core and host adapters").
//!
//! Inbound, an adapter decodes its own wire protocol and calls the operation
//! core with platform-normalized names; outbound, the core hands it
//! invalidations to push at the kernel. Everything platform-shaped —
//! errno/NTSTATUS mapping, case-insensitive presentation, readdir cookie
//! quirks — lives on this side of the trait, and nothing else does.

use core::time::Duration;

use cipherbox_engine::SyncTimingProfile;

/// What the core tells an adapter has changed, so the kernel's cache for it
/// stops being trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalidation {
    /// The node's content bytes changed.
    Data {
        /// The affected inode.
        ino: u64,
    },
    /// The node's attributes changed.
    Attributes {
        /// The affected inode.
        ino: u64,
    },
    /// A directory entry appeared, changed, or vanished.
    Entry {
        /// The directory holding the entry.
        parent: u64,
        /// The entry's name.
        name: String,
    },
}

/// What a mount technology can do for the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostCapabilities {
    /// Whether the adapter can push invalidation at the kernel. An adapter
    /// that cannot must say so: the core then falls back to short cache TTLs
    /// for that mount, because nothing else would ever revalidate.
    pub push_invalidation: bool,
}

/// The kernel-facing cache lifetimes for one mount, derived from what its
/// adapter declared. Never zero — v1's dir-TTL-0 workaround was the symptom of
/// a mount that could not invalidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheTtls {
    /// How long a name→inode binding may be cached.
    pub entry: Duration,
    /// How long attributes may be cached.
    pub attr: Duration,
}

impl CacheTtls {
    /// Cache lifetimes for a mount with these capabilities, read off the sync
    /// timing profile rather than hardcoded: a push-capable mount may hold a
    /// cache entry until the staleness threshold, since a real change arrives
    /// as an invalidation. Without push, nothing revalidates on its own, so
    /// the ceiling is one poll cycle.
    pub fn for_host(capabilities: &HostCapabilities, profile: &SyncTimingProfile) -> Self {
        let ttl = if capabilities.push_invalidation {
            profile.stale_after
        } else {
            profile.poll_cadence
        };
        Self {
            entry: ttl,
            attr: ttl,
        }
    }
}

/// One mount technology's host adapter.
///
/// Invalidation is infallible from the core's side: a mutation has already
/// happened durably by the time the core reports it, so a kernel that refuses
/// the notification is the adapter's problem to absorb, never a reason to fail
/// the operation back to the caller.
pub trait HostAdapter {
    /// What this mount can do.
    fn capabilities(&self) -> HostCapabilities;

    /// Push one invalidation at the kernel.
    fn invalidate(&self, invalidation: Invalidation);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_push_capable_mount_may_cache_up_to_the_staleness_threshold() {
        let profile = SyncTimingProfile::PRODUCTION;
        let ttls = CacheTtls::for_host(
            &HostCapabilities {
                push_invalidation: true,
            },
            &profile,
        );
        assert_eq!(ttls.entry, profile.stale_after);
        assert_eq!(ttls.attr, profile.stale_after);
    }

    #[test]
    fn a_mount_without_push_falls_back_to_a_shorter_ttl() {
        let profile = SyncTimingProfile::PRODUCTION;
        let with_push = CacheTtls::for_host(
            &HostCapabilities {
                push_invalidation: true,
            },
            &profile,
        );
        let without_push = CacheTtls::for_host(
            &HostCapabilities {
                push_invalidation: false,
            },
            &profile,
        );
        assert!(without_push.entry < with_push.entry);
        assert!(without_push.attr < with_push.attr);
    }

    #[test]
    fn no_profile_yields_a_zero_ttl() {
        for profile in [SyncTimingProfile::PRODUCTION, SyncTimingProfile::CI] {
            for push_invalidation in [true, false] {
                let ttls = CacheTtls::for_host(&HostCapabilities { push_invalidation }, &profile);
                assert!(!ttls.entry.is_zero());
                assert!(!ttls.attr.is_zero());
            }
        }
    }
}
