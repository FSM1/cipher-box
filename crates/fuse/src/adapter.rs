//! The host-adapter trait — one implementation per mount technology
//! (blueprint/desktop.md "The FS core and host adapters").
//!
//! Inbound, an adapter decodes its own wire protocol and calls the operation
//! core with platform-normalized names; outbound, the core hands it
//! invalidations to push at the kernel.

use core::time::Duration;

use cipherbox_core::codec::RedactedText;
use cipherbox_engine::SyncTimingProfile;

/// What the core tells an adapter has changed, so the kernel's cache for it
/// stops being trusted.
#[derive(Clone, PartialEq, Eq)]
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

impl core::fmt::Debug for Invalidation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Data { ino } => f.debug_struct("Data").field("ino", ino).finish(),
            Self::Attributes { ino } => f.debug_struct("Attributes").field("ino", ino).finish(),
            Self::Entry { parent, name } => f
                .debug_struct("Entry")
                .field("parent", parent)
                .field("name", &RedactedText::of(name))
                .finish(),
        }
    }
}

/// What a mount technology can do for the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostCapabilities {
    /// Whether the adapter can push invalidation at the kernel. An adapter
    /// that cannot must say so: the core then falls back to short cache TTLs
    /// for that mount, because nothing else would ever revalidate.
    pub push_invalidation: bool,
    /// Whether the kernel caches attributes for this mount at all. A mount that
    /// suppressed the cache — the `noattrcache` the FUSE-T SMB backend requires
    /// (blueprint/desktop.md "Freshness") — says `false`.
    pub attribute_cache: bool,
}

/// The kernel-facing cache lifetimes for one mount, derived from what its
/// adapter declared. Never zero for a cache the kernel keeps — v1's dir-TTL-0
/// workaround was the symptom of a mount that could not invalidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheTtls {
    /// How long a name→inode binding may be cached.
    pub entry: Duration,
    /// How long attributes may be cached; zero for a mount whose kernel keeps
    /// no attribute cache to begin with (`noattrcache`).
    pub attr: Duration,
}

impl CacheTtls {
    /// Without push, nothing revalidates on its own, so the ceiling is one
    /// poll cycle.
    pub fn for_host(capabilities: &HostCapabilities, profile: &SyncTimingProfile) -> Self {
        let ttl = if capabilities.push_invalidation {
            profile.stale_after
        } else {
            profile.poll_cadence
        };
        Self {
            entry: ttl,
            attr: if capabilities.attribute_cache {
                ttl
            } else {
                Duration::ZERO
            },
        }
    }

    /// How long the kernel may cache the attributes of a node this mount is
    /// reporting at `size`.
    ///
    /// A size the content plane has not projected yet is provisional: an
    /// adapter must put *some* number in the reply, and a kernel that caches a
    /// zero there stops reading at byte zero — the shape `cp` turns into an
    /// empty copy of a real file. So a provisional reply is never cached, and
    /// the projection's own push invalidation corrects it.
    pub fn attr_for(&self, size: Option<u64>) -> Duration {
        match size {
            Some(_) => self.attr,
            None => Duration::ZERO,
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

    /// The entry invalidation is the value nearest a host log line, and it
    /// carries a filename.
    #[test]
    fn debug_renders_no_entry_name() {
        let rendered = format!(
            "{:?}",
            Invalidation::Entry {
                parent: 1,
                name: "secret-name.txt".to_owned(),
            }
        );
        assert!(
            !rendered.contains("secret-name.txt"),
            "a filename never renders: {rendered}"
        );
        assert!(rendered.contains("Entry"), "the shape survives: {rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    fn caps(push_invalidation: bool) -> HostCapabilities {
        HostCapabilities {
            push_invalidation,
            attribute_cache: true,
        }
    }

    #[test]
    fn a_push_capable_mount_may_cache_up_to_the_staleness_threshold() {
        let profile = SyncTimingProfile::PRODUCTION;
        let ttls = CacheTtls::for_host(&caps(true), &profile);
        assert_eq!(ttls.entry, profile.stale_after);
        assert_eq!(ttls.attr, profile.stale_after);
    }

    #[test]
    fn a_mount_without_push_falls_back_to_a_shorter_ttl() {
        let profile = SyncTimingProfile::PRODUCTION;
        let with_push = CacheTtls::for_host(&caps(true), &profile);
        let without_push = CacheTtls::for_host(&caps(false), &profile);
        assert!(without_push.entry < with_push.entry);
        assert!(without_push.attr < with_push.attr);
    }

    #[test]
    fn a_noattrcache_mount_hands_back_no_attribute_lifetime() {
        for profile in [SyncTimingProfile::PRODUCTION, SyncTimingProfile::CI] {
            for push_invalidation in [true, false] {
                let ttls = CacheTtls::for_host(
                    &HostCapabilities {
                        push_invalidation,
                        attribute_cache: false,
                    },
                    &profile,
                );
                assert!(ttls.attr.is_zero(), "there is no attribute cache to time");
                assert!(
                    !ttls.entry.is_zero(),
                    "name lookups are still cached; only attributes are suppressed"
                );
            }
        }
    }

    #[test]
    fn every_kept_cache_yields_a_nonzero_ttl() {
        for profile in [SyncTimingProfile::PRODUCTION, SyncTimingProfile::CI] {
            for push_invalidation in [true, false] {
                let ttls = CacheTtls::for_host(&caps(push_invalidation), &profile);
                assert!(!ttls.entry.is_zero());
                assert!(!ttls.attr.is_zero());
            }
        }
    }

    /// A projected size is as trustworthy as any other attribute; an
    /// unprojected one is a placeholder, and a cached placeholder is the bug.
    #[test]
    fn only_a_projected_size_earns_an_attribute_lifetime() {
        let ttls = CacheTtls::for_host(&caps(true), &SyncTimingProfile::PRODUCTION);
        assert_eq!(ttls.attr_for(Some(4096)), ttls.attr);
        assert!(ttls.attr_for(Some(0)) > Duration::ZERO);
        assert_eq!(ttls.attr_for(None), Duration::ZERO);
    }

    /// A mount whose kernel keeps no attribute cache has nothing to time
    /// either way.
    #[test]
    fn a_noattrcache_mount_times_no_size_at_all() {
        let ttls = CacheTtls::for_host(
            &HostCapabilities {
                push_invalidation: true,
                attribute_cache: false,
            },
            &SyncTimingProfile::PRODUCTION,
        );
        assert_eq!(ttls.attr_for(Some(4096)), Duration::ZERO);
        assert_eq!(ttls.attr_for(None), Duration::ZERO);
    }
}
