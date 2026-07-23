//! Shared content-plane size limits.

/// Hard ceiling on a resolved content block, the single source of truth for both
/// the decode side ([`super::read::read_block`], which rejects any fetched block
/// over this before it is hashed, decoded, or gated — gate work is linear in the
/// fetched byte count) and the encode side ([`super::dag::assemble`], which fails
/// closed rather than emit a root manifest over this cap). A resolved record's
/// envelope-content rides in an IPFS block fetched by CID; capping it here bounds
/// gate work to a fixed budget and fails closed on anything larger (#742;
/// blueprint/engine.md "Content plane").
///
/// Must exceed the 1 MiB content chunk size. A legitimate flat-DAG root inlines
/// every leaf CID, so it fits only up to the flat-DAG ceiling (~108 GiB at a
/// 1 MiB chunk size); `assemble` enforces that ceiling as a release-active
/// `Err`, so this crate never publishes a root its own `read_block` rejects
/// (#788 — the encode/decode fail-closed symmetry of AGENTS.md rule 8).
pub(crate) const MAX_RESOLVED_RECORD_BYTES: usize = 4 * 1024 * 1024;
