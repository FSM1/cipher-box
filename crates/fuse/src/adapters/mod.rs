//! The host adapters themselves — one per mount technology, each a thin
//! decoder over the shared operation core (blueprint/desktop.md "The FS core
//! and host adapters").
//!
//! Only what is genuinely platform-shaped lives here. Anything two mount
//! technologies would decide the same way lives at the type it belongs to —
//! [`crate::errno`], [`Access::from_open_flags`](crate::Access::from_open_flags),
//! [`CacheTtls::attr_for`](crate::CacheTtls::attr_for) — so the v1 class where
//! two operation trees disagreed cannot recur.

#[cfg(target_os = "linux")]
pub mod linux;
