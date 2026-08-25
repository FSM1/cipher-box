//! One adapter per mount technology, each a thin decoder over the shared
//! operation core.

#[cfg(target_os = "linux")]
pub mod linux;
