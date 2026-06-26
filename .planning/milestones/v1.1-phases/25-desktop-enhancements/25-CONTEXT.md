# Phase 25: Desktop Enhancements - Context

**Gathered:** 2026-03-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Desktop app auto-updates to new versions and enrolls newly created files with the TEE for automatic IPNS republishing. Two independent capabilities: (1) Tauri updater integration with GitHub Releases, (2) TEE IPNS key wrapping on file creation in FUSE mount.

</domain>

<decisions>
## Implementation Decisions

### Auto-update mechanism

- Use Tauri v2 built-in updater plugin (not custom solution)
- Check for updates on launch only (no periodic background polling)
- Auto-download update in background after detection, prompt user only when ready to install
- Single release channel (stable only) — beta testing via staging builds or manual installs

### TEE file enrollment

- Enroll files with TEE on first IPNS publish (same pattern as folder creation in `write_ops.rs:499`)
- Send `encryptedIpnsPrivateKey` + `keyEpoch` in the publish request — identical API contract to web app
- New files only — no retroactive migration of existing unenrolled files
- Always enroll regardless of BYO-IPFS config (TEE republishes to CipherBox IPNS routing, keeping names resolvable even if user's node goes offline)

### Update distribution

- Host update artifacts on GitHub Releases (leverages existing Release Please infrastructure)
- Tauri Ed25519 signing for update bundle verification (private key signs, public key embedded in app)
- Skip platform code signing (Apple notarization, Windows Authenticode) for now — defer to future phase
- CI automatically builds desktop bundles for all platforms, signs with Ed25519, uploads to GitHub Releases with updater manifest JSON on every Release Please release

### UX around updates

- System tray notification when update is ready: "CipherBox vX.Y.Z is ready. It will be installed on next restart."
- Minimal notification — no changelog/release notes in notification
- Install on restart — mark as pending, clean FUSE unmount on quit, apply update, relaunch. No mid-session disruption.
- Add "Check for Updates..." item to existing tray menu for manual checks

### Claude's Discretion

- Tauri updater plugin configuration details (endpoint URL format, manifest JSON structure)
- CI workflow structure for building and signing desktop bundles
- Ed25519 keypair generation and secret management in GitHub Actions
- Exact tray notification wording and timing (delay after launch before check)
- How pending uploads are drained before restart

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Desktop architecture

- `apps/desktop/CLAUDE.md` — FUSE mount architecture, platform constraints, key file locations
- `apps/desktop/src-tauri/tauri.conf.json` — Current Tauri config (no updater section yet)
- `crates/fuse/src/write_ops.rs` — Folder creation TEE enrollment pattern (line ~499), file upload on release()
- `crates/fuse/src/lib.rs` — `tee_public_key` and `tee_key_epoch` fields on CipherBoxFS

### TEE and IPNS publishing

- `crates/api-client/src/ipns.rs` — `publish_ipns` function with `IpnsPublishRequest` (already has `encrypted_ipns_private_key` and `key_epoch` fields)
- `crates/api-client/src/types.rs` — `IpnsPublishRequest` struct definition
- `apps/api/src/ipns/entities/folder-ipns.entity.ts` — Server-side IPNS entity with `encryptedIpnsPrivateKey` column

### Release infrastructure

- `release-please-config.json` — Release Please configuration for all packages
- `.release-please-manifest.json` — Current version manifest
- `.github/workflows/` — Existing CI workflows (check for desktop build workflows)

### Existing TEE enrollment in web app

- `apps/web/src/services/folder.service.ts` — Web app TEE enrollment pattern (`encryptedIpnsPrivateKey` on publish)
- `tee-worker/src/routes/republish.ts` — TEE republish endpoint
- `tee-worker/src/services/ipns-signer.ts` — TEE IPNS signing logic

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `crates/fuse/src/write_ops.rs` — TEE key wrapping already implemented for folders: `cipherbox_crypto::wrap_key(&ipns_private_key, tee_key)`. Same pattern applies to per-file IPNS keys.
- `crates/api-client/src/types.rs` — `IpnsPublishRequest` already has `encrypted_ipns_private_key: Option<String>` and `key_epoch: Option<u32>` fields
- `apps/desktop/src-tauri/src/tray/` — Existing tray module for adding "Check for Updates" menu item
- `crates/fuse/src/lib.rs` — `CipherBoxFS` already stores `tee_public_key: Option<Vec<u8>>` and `tee_key_epoch: Option<u32>`

### Established Patterns

- IPNS publish with TEE enrollment: wrap IPNS private key with TEE public key using ECIES, include in publish request (folder creation in write_ops.rs)
- Debounced publish via `PublishCoordinator` — file mutations coalesce into single publishes
- Tauri plugin system — deep-link plugin already configured in tauri.conf.json
- Release Please with `include-component-in-tag: true` for root package

### Integration Points

- `tauri.conf.json` → add `updater` plugin configuration with endpoint URL and Ed25519 public key
- `Cargo.toml` → add `tauri-plugin-updater` dependency
- Tray module → add "Check for Updates..." menu item
- `write_ops.rs` file release() flow → add TEE key wrapping for per-file IPNS keys (currently only done for folder creation)
- CI workflows → add desktop build + sign + upload job triggered on Release Please releases

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches. Key constraint: FUSE mount must unmount cleanly before update install (existing `diskutil unmount force` fallback applies).

</specifics>

<deferred>
## Deferred Ideas

- Platform code signing (Apple notarization, Windows Authenticode) — future phase
- Beta/canary update channels — future if needed
- Retroactive TEE enrollment for existing files — not planned, new files only
- Delta updates (Tauri supports these but adds complexity) — evaluate after initial implementation

</deferred>

---

_Phase: 25-desktop-enhancements_
_Context gathered: 2026-03-25_
