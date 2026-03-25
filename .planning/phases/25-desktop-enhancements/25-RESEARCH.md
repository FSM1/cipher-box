# Phase 25: Desktop Enhancements - Research

**Researched:** 2026-03-25
**Domain:** Tauri v2 updater plugin, FUSE mount TEE IPNS enrollment, CI release automation
**Confidence:** HIGH

## Summary

Phase 25 adds two independent capabilities to the desktop app: (1) auto-update via the Tauri v2 built-in updater plugin backed by GitHub Releases, and (2) TEE enrollment for per-file IPNS keys created in the FUSE mount. Both are well-understood patterns with clear integration points in the existing codebase.

The auto-update feature uses `tauri-plugin-updater` (v2.10.0), which provides Ed25519 (Minisign) signature verification, a `latest.json` manifest hosted on GitHub Releases, and a Rust API for checking/downloading/installing updates. The existing Release Please infrastructure creates GitHub Releases on every merge to main; the new CI job attaches signed desktop bundles and the updater manifest JSON to these releases.

The TEE file enrollment is a surgical change: the existing `publish_file_metadata` function in `crates/fuse/src/operations.rs` already publishes per-file IPNS records but passes `encrypted_ipns_private_key: None`. The fix threads the TEE public key through this function and wraps the file's IPNS private key with it -- identical to the pattern already implemented for folder creation in `write_ops.rs:499-506` and in the web app's `file-metadata.service.ts:166-176`.

**Primary recommendation:** Implement TEE file enrollment first (smaller change, clear pattern to follow), then the updater integration (larger CI/config change). Both are independent and can be done in any order.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- Use Tauri v2 built-in updater plugin (not custom solution)
- Check for updates on launch only (no periodic background polling)
- Auto-download update in background after detection, prompt user only when ready to install
- Single release channel (stable only)
- Enroll files with TEE on first IPNS publish (same pattern as folder creation in `write_ops.rs:499`)
- Send `encryptedIpnsPrivateKey` + `keyEpoch` in the publish request -- identical API contract to web app
- New files only -- no retroactive migration of existing unenrolled files
- Always enroll regardless of BYO-IPFS config
- Host update artifacts on GitHub Releases (leverages existing Release Please infrastructure)
- Tauri Ed25519 signing for update bundle verification (private key signs, public key embedded in app)
- Skip platform code signing (Apple notarization, Windows Authenticode) for now
- CI automatically builds desktop bundles for all platforms, signs with Ed25519, uploads to GitHub Releases with updater manifest JSON on every Release Please release
- System tray notification when update is ready: "CipherBox vX.Y.Z is ready. It will be installed on next restart."
- Minimal notification -- no changelog/release notes in notification
- Install on restart -- mark as pending, clean FUSE unmount on quit, apply update, relaunch. No mid-session disruption.
- Add "Check for Updates..." item to existing tray menu for manual checks

### Claude's Discretion

- Tauri updater plugin configuration details (endpoint URL format, manifest JSON structure)
- CI workflow structure for building and signing desktop bundles
- Ed25519 keypair generation and secret management in GitHub Actions
- Exact tray notification wording and timing (delay after launch before check)
- How pending uploads are drained before restart

### Deferred Ideas (OUT OF SCOPE)

- Platform code signing (Apple notarization, Windows Authenticode)
- Beta/canary update channels
- Retroactive TEE enrollment for existing files
- Delta updates

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID         | Description                                                                  | Research Support                                                                                                                                                     |
| ---------- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| DESKTOP-01 | Desktop app checks for and installs updates (Tauri updater or custom)        | `tauri-plugin-updater` v2.10.0 provides check/download/install API; `latest.json` manifest hosted on GitHub Releases; Ed25519 signing via `TAURI_SIGNING_PRIVATE_KEY` |
| DESKTOP-02 | Files created via FUSE mount are enrolled with TEE for automatic IPNS republishing | `publish_file_metadata` in `operations.rs:125` needs TEE key wrapping; pattern exists in `write_ops.rs:499-506` for folders and web app `file-metadata.service.ts:166-176` |

</phase_requirements>

## Standard Stack

### Core

| Library                  | Version | Purpose                          | Why Standard                                                |
| ------------------------ | ------- | -------------------------------- | ----------------------------------------------------------- |
| tauri-plugin-updater     | 2.10.0  | Rust crate for auto-update       | Official Tauri v2 plugin, Ed25519 signing, manifest support |
| @tauri-apps/plugin-updater | 2.10.0 | JS bindings (optional, for UI)  | Matches Rust crate version                                  |
| tauri-apps/tauri-action  | v1      | GitHub Action for building/signing | Official CI action, generates `latest.json` + `.sig` files |

### Supporting

| Library                    | Version | Purpose                         | When to Use                          |
| -------------------------- | ------- | ------------------------------- | ------------------------------------ |
| tauri-plugin-process       | 2.x     | `app.restart()` after update    | Already available via tauri core     |
| cipherbox-crypto           | workspace | `wrap_key` for TEE enrollment | Already used in folder creation flow |

### Alternatives Considered

| Instead of               | Could Use              | Tradeoff                                                    |
| ------------------------ | ---------------------- | ----------------------------------------------------------- |
| tauri-plugin-updater     | Sparkle (macOS) + custom | Cross-platform complexity, macOS only for Sparkle         |
| GitHub Releases hosting  | CrabNebula Cloud       | Additional service dependency, cost                         |
| Ed25519 (Minisign)       | GPG/platform signing   | Deferred: Apple notarization + Authenticode are separate    |

**Installation:**
```bash
# Rust crate (in apps/desktop/src-tauri/Cargo.toml)
cargo add tauri-plugin-updater

# JS bindings (optional, only if update UI uses JavaScript)
cd apps/desktop && pnpm add @tauri-apps/plugin-updater
```

**Version verification:** tauri-plugin-updater 2.10.0 confirmed via crates.io (released 2026-02-03). @tauri-apps/plugin-updater 2.10.0 confirmed via npm. Compatible with tauri 2.10.x (currently using 2.10.2 per Cargo.lock).

## Architecture Patterns

### Recommended Project Structure

```
apps/desktop/src-tauri/
  src/
    main.rs           # Add updater plugin registration
    tray/
      mod.rs          # Add "Check for Updates..." menu item
      status.rs       # Existing status module
    updater.rs        # NEW: Update check on launch, notification, restart logic
  tauri.conf.json     # Add updater config (pubkey, endpoint, createUpdaterArtifacts)
  capabilities/
    default.json      # Add updater permissions

crates/fuse/src/
  operations.rs       # Modify publish_file_metadata to accept TEE params
  write_ops.rs        # Already has folder TEE enrollment (reference pattern)
  read_ops.rs         # Thread TEE params from CipherBoxFS into release() upload flow
  lib.rs              # CipherBoxFS already has tee_public_key/tee_key_epoch fields

.github/workflows/
  build-desktop.yml   # NEW: Desktop build + sign + upload to GitHub Release
```

### Pattern 1: Tauri Updater Plugin Setup

**What:** Register the updater plugin, configure `tauri.conf.json`, and check for updates on app launch.

**When to use:** App startup.

**Configuration (`tauri.conf.json`):**
```json
{
  "bundle": {
    "createUpdaterArtifacts": true
  },
  "plugins": {
    "updater": {
      "pubkey": "<MINISIGN_ED25519_PUBLIC_KEY>",
      "endpoints": [
        "https://github.com/<owner>/<repo>/releases/latest/download/latest.json"
      ]
    }
  }
}
```

**Rust plugin registration (`main.rs`):**
```rust
// In tauri::Builder::default() chain:
.plugin(tauri_plugin_updater::Builder::new().build())
```

**On-launch check (`updater.rs`):**
```rust
use tauri_plugin_updater::UpdaterExt;

pub async fn check_for_update(app: &tauri::AppHandle) {
    match app.updater().and_then(|u| Ok(u)) {
        Ok(updater) => {
            match updater.check().await {
                Ok(Some(update)) => {
                    log::info!("Update available: v{}", update.version);
                    // Download in background
                    match update.download_and_install(
                        |chunk_len, content_len| { /* progress tracking */ },
                        || { log::info!("Download complete, pending restart"); }
                    ).await {
                        Ok(()) => {
                            // Notify user via tray
                            send_update_notification(app, &update.version);
                        }
                        Err(e) => log::warn!("Update download failed: {}", e),
                    }
                }
                Ok(None) => log::info!("No update available"),
                Err(e) => log::warn!("Update check failed: {}", e),
            }
        }
        Err(e) => log::warn!("Updater not available: {}", e),
    }
}
```

**Capability permissions (`default.json`):**
```json
"updater:default"
```

### Pattern 2: TEE File Enrollment on First Publish

**What:** Wrap the file's IPNS private key with the TEE public key during the first per-file IPNS publish.

**When to use:** When `publish_file_metadata` is called for a newly created file.

**Existing folder enrollment pattern (`write_ops.rs:499-506`):**
```rust
let encrypted_ipns_for_tee = if let Some(ref tee_key) = fs.tee_public_key {
    let wrapped = cipherbox_crypto::wrap_key(&ipns_private_key, tee_key)
        .map_err(|e| format!("TEE key wrapping failed: {}", e))?;
    Some(hex::encode(&wrapped))
} else {
    None
};
let tee_key_epoch = fs.tee_key_epoch;
```

**Required change in `publish_file_metadata` (`operations.rs:125`):**
Add `tee_public_key: Option<&[u8]>` and `tee_key_epoch: Option<u32>` parameters, then:
```rust
let encrypted_ipns_for_tee = if let Some(tee_key) = tee_public_key {
    let wrapped = cipherbox_crypto::wrap_key(file_ipns_private_key.as_slice(), tee_key)
        .map_err(|e| format!("TEE key wrapping failed: {}", e))?;
    Some(hex::encode(&wrapped))
} else {
    None
};

let req = cipherbox_api_client::IpnsPublishRequest {
    // ... existing fields ...
    encrypted_ipns_private_key: encrypted_ipns_for_tee,
    key_epoch: tee_key_epoch,
    // ...
};
```

### Pattern 3: CI Desktop Build with tauri-action

**What:** GitHub Actions workflow that builds desktop bundles for all platforms, signs with Ed25519, and uploads to GitHub Release.

**When to use:** Triggered by Release Please creating a GitHub Release.

**Workflow trigger approach:** The existing `release-please.yml` creates releases. A new `build-desktop.yml` workflow triggers on `release` events or is called by release-please with a `releaseId` to attach artifacts to the existing release.

**tauri-action configuration:**
```yaml
- uses: tauri-apps/tauri-action@v1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}
    TAURI_SIGNING_PRIVATE_KEY_PASSWORD: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}
  with:
    releaseId: ${{ needs.release.outputs.release_id }}
    uploadUpdaterJson: true
```

### Pattern 4: Install-on-Restart with Clean FUSE Unmount

**What:** When the user quits the app (via tray "Quit CipherBox"), unmount FUSE cleanly before allowing the update to install.

**When to use:** On quit when an update is pending.

**Existing quit handler (`tray/mod.rs:272-279`):**
```rust
"quit" => {
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    {
        let _ = crate::fuse::unmount_filesystem();
    }
    app.exit(0);
}
```

The updater plugin handles restart automatically via `app.restart()`. The quit flow should:
1. Drain pending uploads (wait for upload_tx queue to empty)
2. Unmount FUSE
3. Call `app.restart()` which triggers the pending update install

### Anti-Patterns to Avoid

- **Checking for updates from JavaScript:** The Rust API is more appropriate since the desktop app runs as a menu-bar utility without a visible window. Use `UpdaterExt` from Rust, not the JS `check()` function.
- **Polling for updates:** Decision is launch-only check. Do NOT add a timer/interval.
- **TEE enrollment on every publish:** Only enroll on FIRST publish (sequence 0 or first time for that IPNS name). Subsequent publishes for the same file should pass `None` since the TEE already has the key.
- **Blocking FUSE thread for TEE wrapping:** The `wrap_key` call happens in the background upload thread (spawned in `release()`), NOT on the FUSE callback thread. This is already the correct pattern.

## Don't Hand-Roll

| Problem                | Don't Build                    | Use Instead                    | Why                                                   |
| ---------------------- | ------------------------------ | ------------------------------ | ----------------------------------------------------- |
| Update verification    | Custom signature checking      | tauri-plugin-updater Ed25519   | Minisign is proven, handles edge cases                |
| Update manifest        | Custom JSON format             | Tauri's `latest.json` format   | Standardized, tauri-action generates it automatically |
| Update hosting         | Custom CDN/S3 upload           | GitHub Releases + tauri-action | Already have Release Please, zero additional infra    |
| Key wrapping           | Custom ECIES implementation    | `cipherbox_crypto::wrap_key`   | Already used everywhere, tested                       |
| Bundle signing in CI   | Manual openssl/minisign steps  | `TAURI_SIGNING_PRIVATE_KEY` env | tauri-action reads it automatically                  |

**Key insight:** Both features are integration work, not novel implementations. The updater uses a mature plugin with a well-defined protocol. The TEE enrollment reuses an existing pattern verbatim.

## Common Pitfalls

### Pitfall 1: Updater Endpoint URL Must Use GitHub's /latest/download/ Path

**What goes wrong:** Using a direct release URL (e.g., `/releases/tag/v1.0.0/latest.json`) breaks because the updater checks the "latest" release dynamically.
**Why it happens:** GitHub's `/releases/latest/download/` is a special redirect that always serves the latest release's assets.
**How to avoid:** Use exactly: `https://github.com/<owner>/<repo>/releases/latest/download/latest.json`
**Warning signs:** 404 errors on update check, "no update available" when there should be one.

### Pitfall 2: TAURI_SIGNING_PRIVATE_KEY Must Be Set at Build Time

**What goes wrong:** Build succeeds but no `.sig` files are generated, making updates unverifiable.
**Why it happens:** Tauri only generates updater signatures when `TAURI_SIGNING_PRIVATE_KEY` is set as an environment variable during `tauri build`. It does NOT read from `.env` files.
**How to avoid:** Set as GitHub Actions secret, expose via `env:` in the workflow step.
**Warning signs:** No `.sig` files in the build output, `latest.json` generated without signature fields.

### Pitfall 3: createUpdaterArtifacts Must Be "true" in bundle Config

**What goes wrong:** Build produces normal installers but no updater bundles (`.tar.gz` on macOS, `.AppImage` on Linux).
**Why it happens:** Without `createUpdaterArtifacts`, Tauri doesn't generate the special updater format.
**How to avoid:** Add `"createUpdaterArtifacts": true` to `bundle` section of `tauri.conf.json`.
**Warning signs:** Missing `.tar.gz` for macOS, missing signatures.

### Pitfall 4: Release Please Tag Format vs Updater latest.json

**What goes wrong:** The updater's `latest.json` contains a version (e.g., `0.29.0`) but Release Please creates tags with a prefix (e.g., `cipher-box-v0.29.0`).
**Why it happens:** The updater compares semver versions, while GitHub Releases uses tag names. The `latest.json` URLs must point to the actual release assets.
**How to avoid:** Use `tauri-action`'s `releaseId` input to attach to the existing Release Please release rather than creating a new one. The action generates `latest.json` with correct download URLs.
**Warning signs:** Version mismatch, 404 on download URLs.

### Pitfall 5: TEE Enrollment Must Be Idempotent on the Server

**What goes wrong:** Sending `encryptedIpnsPrivateKey` on a subsequent publish (not first) could overwrite the TEE's stored key or cause errors.
**Why it happens:** The server-side `folder-ipns.entity.ts` stores `encryptedIpnsPrivateKey` -- sending it again on a non-first publish is harmless (server upserts), but wastes bandwidth.
**How to avoid:** Only include TEE fields on the first publish for a given file IPNS name (when sequence number is 0). On subsequent publishes, pass `None`.
**Warning signs:** No functional error, but unnecessary ECIES wrapping on every file save.

### Pitfall 6: Windows Update Behavior Differs

**What goes wrong:** On Windows, `download_and_install` immediately exits the application to run the NSIS installer. There is no "install on next restart" option.
**Why it happens:** Windows NSIS installers need exclusive file access; Tauri force-exits the app.
**How to avoid:** On Windows, show a confirmation dialog before calling `download_and_install`. On macOS/Linux, the update can be applied on restart.
**Warning signs:** App closes unexpectedly on Windows during update.

## Code Examples

### Complete `publish_file_metadata` with TEE Enrollment

```rust
// Source: crates/fuse/src/operations.rs (modified)
pub async fn publish_file_metadata(
    api: &cipherbox_api_client::ApiClient,
    file_meta: &cipherbox_core::FileMetadata,
    folder_key: &[u8],
    file_ipns_private_key: &zeroize::Zeroizing<Vec<u8>>,
    file_ipns_name: &str,
    coordinator: &crate::PublishCoordinator,
    tee_public_key: Option<&[u8]>,      // NEW
    tee_key_epoch: Option<u32>,          // NEW
    is_first_publish: bool,              // NEW: only enroll on first publish
) -> Result<(), String> {
    // ... existing encryption + upload logic ...

    // TEE enrollment on first publish only
    let encrypted_ipns_for_tee = if is_first_publish {
        if let Some(tee_key) = tee_public_key {
            let wrapped = cipherbox_crypto::wrap_key(
                file_ipns_private_key.as_slice(), tee_key
            ).map_err(|e| format!("TEE key wrapping failed: {}", e))?;
            Some(hex::encode(&wrapped))
        } else {
            None
        }
    } else {
        None
    };

    let req = cipherbox_api_client::IpnsPublishRequest {
        ipns_name: file_ipns_name.to_string(),
        record: record_b64,
        metadata_cid: file_meta_cid.clone(),
        encrypted_ipns_private_key: encrypted_ipns_for_tee,
        key_epoch: if encrypted_ipns_for_tee.is_some() { tee_key_epoch } else { None },
        expected_sequence_number: None,
    };
    // ... existing publish + coordinator logic ...
}
```

### Updater Module Skeleton

```rust
// Source: apps/desktop/src-tauri/src/updater.rs (new)
use tauri::AppHandle;
use tauri_plugin_updater::UpdaterExt;

/// Check for updates on app launch. Downloads in background, notifies via tray.
pub fn check_on_launch(app: &AppHandle) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        // Small delay to avoid competing with login/mount startup
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        if let Err(e) = do_update_check(&handle).await {
            log::warn!("Update check failed: {}", e);
        }
    });
}

async fn do_update_check(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let updater = app.updater()?;
    let update = updater.check().await?;

    if let Some(update) = update {
        log::info!("Update available: v{}", update.version);

        update.download_and_install(
            |chunk_length, content_length| {
                log::debug!(
                    "Downloading update: {} / {:?} bytes",
                    chunk_length,
                    content_length
                );
            },
            || {
                log::info!("Update downloaded, pending install on restart");
            },
        ).await?;

        // Send tray notification
        use tauri_plugin_notification::NotificationExt;
        let _ = app.notification()
            .builder()
            .title("CipherBox Update Ready")
            .body(&format!(
                "CipherBox v{} is ready. It will be installed on next restart.",
                update.version
            ))
            .show();
    } else {
        log::info!("No update available (current version is latest)");
    }

    Ok(())
}

/// Manual check triggered from tray menu.
pub fn manual_check(app: &AppHandle) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        match do_update_check(&handle).await {
            Ok(()) => {}
            Err(e) => {
                use tauri_plugin_notification::NotificationExt;
                let _ = handle.notification()
                    .builder()
                    .title("CipherBox")
                    .body("No update available or check failed.")
                    .show();
                log::warn!("Manual update check failed: {}", e);
            }
        }
    });
}
```

### CI Workflow for Desktop Build + Sign

```yaml
# Source: .github/workflows/build-desktop.yml (new)
name: Build Desktop

on:
  release:
    types: [published]

permissions:
  contents: write

jobs:
  build:
    strategy:
      fail-fast: false
      matrix:
        include:
          - platform: macos-latest
            args: '--target aarch64-apple-darwin'
          - platform: macos-latest
            args: '--target x86_64-apple-darwin'
          - platform: ubuntu-22.04
            args: ''
          - platform: windows-latest
            args: ''
    runs-on: ${{ matrix.platform }}
    steps:
      # ... setup steps (node, pnpm, rust, platform deps) ...
      - uses: tauri-apps/tauri-action@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}
          TAURI_SIGNING_PRIVATE_KEY_PASSWORD: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}
        with:
          releaseId: ${{ github.event.release.id }}
          uploadUpdaterJson: true
          args: ${{ matrix.args }}
```

### Ed25519 Key Generation (One-Time Setup)

```bash
# Generate signing keypair (run locally, not in CI)
npx @tauri-apps/cli signer generate -w ~/.tauri/cipherbox.key

# Output will show:
# Private key saved to ~/.tauri/cipherbox.key
# Public key: dW50cnVzdGVkIGNvbW1lbnQ6...
#
# Add the PRIVATE KEY CONTENT to GitHub secret: TAURI_SIGNING_PRIVATE_KEY
# Add the PUBLIC KEY string to tauri.conf.json plugins.updater.pubkey
```

## State of the Art

| Old Approach               | Current Approach                      | When Changed     | Impact                                   |
| -------------------------- | ------------------------------------- | ---------------- | ---------------------------------------- |
| Tauri v1 built-in updater  | tauri-plugin-updater v2 (separate)    | Tauri v2 (2024)  | Plugin system, more flexible             |
| `includeUpdaterJson`       | `uploadUpdaterJson` in tauri-action   | tauri-action v1  | Renamed parameter                        |
| tauri-action@v0            | tauri-action@v1                       | 2025             | Stable release, better defaults          |
| Manual `.sig` generation   | Automatic via `TAURI_SIGNING_PRIVATE_KEY` | Tauri v2     | Build-time signing, no manual steps      |
| Custom update servers      | GitHub Releases `/latest/download/`   | Long-standing    | Zero infrastructure for open-source apps |

**Deprecated/outdated:**

- `tauri-action@v0`: Superseded by `v1`. Use `v1` for new projects.
- `includeUpdaterJson`: Renamed to `uploadUpdaterJson` in tauri-action v1.
- Tauri v1's built-in updater: Replaced by plugin architecture in v2.

## Open Questions

1. **Windows install-on-restart behavior**
   - What we know: On Windows, `download_and_install` force-exits the app. On macOS/Linux, the update can be deferred.
   - What's unclear: Whether Tauri v2.10 supports a "stage for next restart" mode on Windows, or if we need platform-specific logic.
   - Recommendation: Test on Windows. If force-exit is unavoidable, show a confirmation prompt on Windows before applying. On macOS/Linux, stage silently and apply on next quit.

2. **Release Please release ID propagation**
   - What we know: tauri-action accepts a `releaseId` to attach artifacts to an existing release.
   - What's unclear: How to extract the release ID from the Release Please workflow output.
   - Recommendation: Use the `release` event trigger (fires when Release Please publishes), which provides `github.event.release.id` directly. Alternatively, query the GitHub API for the latest release.

3. **Updater endpoint with `include-component-in-tag`**
   - What we know: Release Please uses `include-component-in-tag: true`, creating tags like `cipher-box-v0.29.0`. GitHub's `/releases/latest/download/` serves the latest release regardless of tag format.
   - What's unclear: Whether the updater correctly picks up releases tagged with a component prefix.
   - Recommendation: The `/latest/download/` redirect works based on the "latest" release flag, not tag format. Verify in integration testing.

## Validation Architecture

### Test Framework

| Property           | Value                                                            |
| ------------------ | ---------------------------------------------------------------- |
| Framework          | Shell scripts (bash + PowerShell) for desktop E2E                |
| Config file        | `tests/desktop-e2e/scripts/run-all.sh`                          |
| Quick run command  | `bash tests/desktop-e2e/scripts/run-all.sh`                     |
| Full suite command | `bash tests/desktop-e2e/scripts/run-all.sh` (same -- all tests) |

### Phase Requirements -> Test Map

| Req ID     | Behavior                            | Test Type  | Automated Command                                           | File Exists? |
| ---------- | ----------------------------------- | ---------- | ----------------------------------------------------------- | ------------ |
| DESKTOP-01 | Update check on launch              | manual     | Manual: requires real GitHub Release with `latest.json`     | N/A          |
| DESKTOP-01 | "Check for Updates" tray menu item  | manual     | Manual: verify menu item appears and triggers check         | N/A          |
| DESKTOP-01 | CI builds desktop bundles           | CI         | `gh workflow run build-desktop.yml` (verifiable via CI run) | Wave 0       |
| DESKTOP-02 | TEE enrollment on file create       | unit       | `cargo test -p cipherbox-fuse tee_enrollment`               | Wave 0       |
| DESKTOP-02 | IPNS publish includes TEE fields    | e2e/manual | Verify API request body in desktop binary log               | N/A          |

### Sampling Rate

- **Per task commit:** `cargo build -p cipherbox-desktop --no-default-features --features fuse` (compile check)
- **Per wave merge:** Full desktop E2E suite
- **Phase gate:** Desktop E2E green + manual updater verification

### Wave 0 Gaps

- [ ] `build-desktop.yml` -- CI workflow for building signed desktop bundles (does not exist yet)
- [ ] Ed25519 signing keypair -- must be generated and stored as GitHub secret
- [ ] Unit test for TEE key wrapping in file publish flow -- verify `encrypted_ipns_private_key` is populated
- [ ] `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` GitHub secrets

## Sources

### Primary (HIGH confidence)

- [Tauri v2 Updater Plugin Documentation](https://v2.tauri.app/plugin/updater/) -- plugin setup, configuration, API
- [tauri-plugin-updater crates.io](https://crates.io/crates/tauri-plugin-updater) -- version 2.10.0 confirmed
- [tauri-plugin-updater Rust API docs](https://docs.rs/tauri-plugin-updater) -- UpdaterExt trait, Update struct
- [tauri-apps/tauri-action GitHub](https://github.com/tauri-apps/tauri-action) -- CI action inputs, `uploadUpdaterJson`, `releaseId`
- [Tauri GitHub Pipelines docs](https://v2.tauri.app/distribute/pipelines/github/) -- cross-platform build matrix

### Secondary (MEDIUM confidence)

- [Tauri auto-updater blog post](https://thatgurjot.com/til/tauri-auto-updater/) -- practical setup walkthrough (partial, missing CI automation)
- [CrabNebula auto-updates guide](https://docs.crabnebula.dev/cloud/guides/auto-updates-tauri/) -- alternative hosting approach (not used here)
- Codebase analysis: `crates/fuse/src/write_ops.rs:499-506` (folder TEE enrollment), `crates/fuse/src/operations.rs:125-180` (file publish without TEE), `apps/web/src/services/file-metadata.service.ts:166-176` (web app TEE enrollment)

### Tertiary (LOW confidence)

- Windows install-on-restart behavior -- inferred from docs noting "Windows exits automatically", needs testing

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- official Tauri plugin with verified versions, well-documented API
- Architecture: HIGH -- both features follow existing patterns (folder TEE enrollment, Tauri plugin registration)
- Pitfalls: HIGH -- common issues documented in official docs and community reports
- CI integration: MEDIUM -- tauri-action v1 is stable but Release Please interop needs testing
- Windows update behavior: LOW -- needs hands-on testing

**Research date:** 2026-03-25
**Valid until:** 2026-04-25 (stable domain, Tauri v2 API is mature)
