---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 25
subsystem: testing
tags: [desktop-e2e, node-v3, sealed-child-ref, ipns, sdk-core, tsx]

requires:
  - phase: 69-24
    provides: desktop mints/recovers/mounts real node/v3 root keys (rootReadKey/rootWriteKey vault blob)
provides:
  - verify-filepointer.mts migrated to the node/v3 read chain (rootReadKey + SealedChildRef + unsealChildReadKey + raw NodeContent.fileKey)
  - edit-filepointer.mts migrated to the node/v3 write chain (unsealChildWriteKey + updateFileMetadata with raw fileKey)
  - rename-folder.mts migrated to the node/v3 write chain (renameInFolder by ipnsName + write-body-preserving republish)
  - the three helpers re-admitted to the tsconfig.scripts.json compile gate (un-quarantined from Phase 62)
  - a copy-pasteable LOCAL desktop-e2e run recipe for the orchestrator
affects: [desktop-e2e, test-round-trip, test-cross-client-sync, test-move-content, SC-05]

tech-stack:
  added: []
  patterns:
    - "node/v3 read-chain hop in an e2e helper: fetch child PublishedNode for plaintext id+kind, then unsealChildReadKey under the PARENT-mirror generation (childRef.generation), never the child envelope generation"
    - "node/v3 write-chain recovery in an e2e helper: unseal root read+write body, find WriteChildRef by childId, unsealChildWriteKey, then updateFileMetadata / updateFolderMetadataAndPublish preserving the write-body"

key-files:
  created:
    - .planning/phases/69-fuse-and-winfsp-rust-integration-and-grant-root-awareness/69-25-SUMMARY.md
  modified:
    - packages/sdk-core/scripts/verify-filepointer.mts
    - packages/sdk-core/scripts/edit-filepointer.mts
    - packages/sdk-core/scripts/rename-folder.mts
    - tsconfig.scripts.json

key-decisions:
  - "Un-quarantined the three helpers from tsconfig.scripts.json's exclude list — the compile gate is the real typecheck gate (tsx does none); leaving them excluded would make the plan's own gate meaningless (Rule 3)"
  - "Kept the single required updateFileMetadata SDK parameter key `fileMetaIpnsName` — it is a current node/v3 signature (file/index.ts), not a retired FilePointer field; every retired-FIELD read was eliminated"
  - "Renamed the helpers' JSON output key from fileMetaIpnsName to fileIpnsName (node/v3 terminology); the shell harness does not parse that key, so the CLI/JSON contract stays compatible"

patterns-established:
  - "Desktop-e2e helpers consume the node/v3 SDK read/write chain directly (loadVaultKeyBlob -> rootReadKey/rootWriteKey), mirroring packages/sdk-core/src/share/navigate.ts and packages/sdk/src/client.ts write-chain recovery"

requirements-completed: [SC-05]

duration: 45min
completed: 2026-07-07
status: complete
---

# Phase 69 Plan 25: Migrate desktop-e2e verifiers to node/v3 + document the local run recipe Summary

**The three desktop-e2e helpers (verify/edit/rename-filepointer) now read the node/v3 vault key blob (rootReadKey/rootWriteKey) and traverse the SealedChildRef read/write chain, so the API round-trip meaningfully exercises a real v3 vault; they typecheck clean and the orchestrator has a copy-pasteable LOCAL run recipe.**

## Performance

- **Duration:** ~45 min
- **Tasks:** 2/2
- **Files modified:** 4 (3 helpers + tsconfig.scripts.json)

## Boundary (read this first)

This plan's boundary is **typecheck/build + a documented recipe**. It does **NOT** run the desktop-e2e suite and does **NOT** claim the node/v3 flip is validated. The actual pass/fail (the SC-05 sign-off) is the **orchestrator's** to determine by running the suite AFTER this merges. Necessary, not sufficient.

## Accomplishments

- **verify-filepointer.mts** now loads `{ rootReadKey }` via `loadVaultKeyBlob`, loads the root `Node` via `loadFolderMetadata({ folderKey: rootReadKey })`, finds the target child in `metadata.children` (`SealedChildRef`) by name, derives the child read key via `unsealChildReadKey(childRef.readKeySealed, parentReadKey, childPublished.id, childPublished.kind, childRef.generation)` (parent-mirror generation), resolves the file `NodeContent` via `resolveFileMetadata`, and decrypts with the **raw** `NodeContent.fileKey` via `downloadFileContent` (no ECIES). The `--folder-name` subfolder descent derives the subfolder read key the same way.
- **edit-filepointer.mts** migrated to the node/v3 **write** chain: unseal the root read+write body, recover the file's `fileReadKey`/`fileWriteKey` via `unsealChildReadKey`/`unsealChildWriteKey` (parent-mirror generation), recover the file's own IPNS signing key from its unsealed write-body, encrypt new content under a fresh **raw** `fileKey`, republish the file record via `updateFileMetadata`, and republish the root folder metadata preserving the write-body (`writeKey` + `writeChildren`).
- **rename-folder.mts** migrated to the node/v3 write chain: unseal the root read+write body, `renameInFolder` keyed by the child's `ipnsName`, republish preserving the write-body.
- **Un-quarantined** the three helpers in `tsconfig.scripts.json` (they were excluded from the compile gate in Phase 62). They now typecheck against the real node/v3 SDK types.
- Verified all three module-load cleanly under `tsx` (imports resolve; reach their usage/required-arg error with no args).

## Verification evidence (in this worktree)

- `grep -rn 'rootFolderKey\|folderKeyEncrypted\|fileMetaIpnsName\|fileKeyEncrypted' packages/sdk-core/scripts/` → **1 line** (`edit-filepointer.mts:196 fileMetaIpnsName: fileIpnsName` — the required `updateFileMetadata` SDK param, NOT a retired field). All retired **field reads** are gone. See Deviations.
- `grep -c 'rootReadKey\|unsealChildReadKey\|downloadFileContent' packages/sdk-core/scripts/verify-filepointer.mts` → **9** (node/v3 read chain wired).
- `pnpm exec tsc -p tsconfig.scripts.json --noEmit` → **exit 0** (helpers typecheck against node/v3 types, now inside the gate).
- `pnpm exec tsx packages/sdk-core/scripts/{verify,edit,rename}-*.mts` (no args) → each reaches its usage error (module + imports resolve; no import/type crash at load).
- `git status` → no change under `packages/sdk-core/src/`; no `package.json` dependency change.

## LOCAL desktop-e2e run recipe (for the ORCHESTRATOR)

Full LOCAL native stack, no docker (mirrors `.github/workflows/desktop-e2e.yml`). Run AFTER this plan merges; the round-trip meaningfully exercises node/v3 only because these helpers now build.

### Stack (native, per platform)

- **PostgreSQL 16** — database `cipherbox_test`, user/pass `postgres`/`postgres`, then run the API migrations.
- **apps/api on `:3000`** — built and running, health-gated (`GET /health`); `NODE_ENV=test`; `TEST_LOGIN_SECRET=e2e-test-secret-ci-only`.
- **Kubo/IPFS v0.34.0** — `:5001` (API) / `:8080` (gateway), `IPFS_PROVIDER=local`.
- **Redis** — `:6379`.
- **mock-ipns-routing** (`tools/mock-ipns-routing`) — `:3001` (`DELEGATED_ROUTING_URL`).
- **Platform FUSE driver** — FUSE-T on macOS (`brew install --cask fuse-t`, SMB backend), libfuse3 on Linux (`libfuse3-dev`), WinFsp on Windows.
- **Desktop frontend** built + served with `VITE_TEST_LOGIN_SECRET=e2e-test-secret-ci-only` (**MUST equal** the API `TEST_LOGIN_SECRET`).

### Headless auth (`--dev-key`)

Launch the debug desktop binary with `--dev-key <hex>`. The frontend POSTs `/auth/test-login { email: 'dev-key@cipherbox.local', secret: VITE_TEST_LOGIN_SECRET }` and uses the **server's returned `privateKeyHex`** (NOT the CLI dev key) so the vault ECIES keypair matches. If `VITE_TEST_LOGIN_SECRET != API TEST_LOGIN_SECRET`, headless auth silently fails the run.

### Copy-pasteable commands (macOS / Linux)

```bash
# 0. Prereqs: Postgres 16, Redis, Kubo v0.34.0, FUSE-T (macOS) / libfuse3 (Linux) installed.
#    Start Postgres, Redis, and Kubo (ipfs daemon on :5001/:8080) first.
cd <repo-root>

# 1. Build workspace packages the helpers + API depend on
pnpm --filter @cipherbox/crypto --filter @cipherbox/core \
     --filter @cipherbox/api-client --filter @cipherbox/sdk-core build
pnpm --filter @cipherbox/api build

# 2. Postgres DB + migrations
createdb cipherbox_test 2>/dev/null || true
DB_HOST=localhost DB_PORT=5432 DB_USERNAME=postgres DB_PASSWORD=postgres \
  DB_DATABASE=cipherbox_test pnpm --filter @cipherbox/api migration:run

# 3. mock-ipns-routing on :3001
( cd tools/mock-ipns-routing && npm install && npm run build && node dist/index.js & )

# 4. API on :3000 (health-gated). Secret MUST match VITE_TEST_LOGIN_SECRET below.
( cd apps/api && \
  NODE_ENV=test DB_HOST=localhost DB_PORT=5432 DB_USERNAME=postgres DB_PASSWORD=postgres \
  DB_DATABASE=cipherbox_test JWT_SECRET=desktop-e2e-jwt-secret-key \
  IPFS_PROVIDER=local IPFS_LOCAL_API_URL=http://localhost:5001 \
  IPFS_LOCAL_GATEWAY_URL=http://localhost:8080 DELEGATED_ROUTING_URL=http://localhost:3001 \
  REDIS_HOST=localhost REDIS_PORT=6379 TEST_LOGIN_SECRET=e2e-test-secret-ci-only \
  node dist/main.js & )
# wait until: curl -s http://localhost:3000/health

# 5. Build the desktop binary (choose fuse feature: fuse on macOS/Linux, winfsp on Windows)
cargo build -p cipherbox-desktop --no-default-features --features fuse

# 6. Build + serve the desktop frontend (VITE_TEST_LOGIN_SECRET == API TEST_LOGIN_SECRET)
( cd apps/desktop && VITE_API_URL=http://localhost:3000 \
  VITE_TEST_LOGIN_SECRET=e2e-test-secret-ci-only pnpm vite preview --port 1420 & )

# 7. Launch the desktop app headless with a dev key (mounts the FUSE volume)
DEV_KEY=$(openssl rand -hex 32)
CIPHERBOX_API_URL=http://localhost:3000 VITE_API_URL=http://localhost:3000 \
  VITE_TEST_LOGIN_SECRET=e2e-test-secret-ci-only RUST_LOG=info \
  target/debug/cipherbox-desktop --dev-key "$DEV_KEY" &

# 8. Run the full desktop-e2e suite (orchestrates test-fuse-operations.sh,
#    test-round-trip.sh -> verify-filepointer.mts, test-cross-client-sync.sh ->
#    verify/edit/rename, test-move-content.ts).
#    Defaults: MOUNT_POINT=$HOME/CipherBox, API_URL=http://localhost:3000,
#    TEST_SECRET=e2e-test-secret-ci-only, test email dev-key@cipherbox.local.
bash tests/desktop-e2e/scripts/run-all.sh
```

Windows uses `tests/desktop-e2e/scripts/run-all.ps1` and the `winfsp` cargo feature.

### CI dispatch alternative (dispatch-gated)

The desktop-e2e job is gated (`push:[main]` + `workflow_dispatch`; runs when `desktop-changed || workflow_dispatch`). To trigger it in CI:

```bash
env -u GITHUB_TOKEN gh workflow run "CI E2E Tests"
```

## Deviations from Plan

### Auto-fixed / necessary changes

**1. [Rule 3 - Blocking] Un-quarantined the three helpers in `tsconfig.scripts.json`**

- **Found during:** Task 1 (the plan's typecheck gate could not actually cover the helpers otherwise).
- **Issue:** Phase 62 added `packages/sdk-core/scripts/{verify,edit,rename}-*.mts` to `tsconfig.scripts.json`'s `exclude` list (they were on the retired FilePointer model). Left excluded, `pnpm exec tsc -p tsconfig.scripts.json --noEmit` would skip them and the plan's "the helpers typecheck against node/v3 types" gate would be a no-op.
- **Fix:** Removed the three from `exclude` (kept `bump-ipns-sequence.ts` excluded — still on the old model, out of scope) and updated the stale comment. `tsconfig.scripts.json` is the compile-gate config, not SDK library source.
- **Files modified:** `tsconfig.scripts.json`
- **Commit:** `10f0defdb`

**2. [Plan-gate nuance] One unavoidable `fileMetaIpnsName` occurrence remains — it is a required SDK parameter, not a retired field**

- **Found during:** Task 1 grep gate.
- **Issue:** The plan's gate `grep -rn 'rootFolderKey\|folderKeyEncrypted\|fileMetaIpnsName\|fileKeyEncrypted' packages/sdk-core/scripts/` expects **empty**. But the canonical node/v3 file-content update API `updateFileMetadata` (packages/sdk-core/src/file/index.ts) has a **required object-literal parameter literally named `fileMetaIpnsName`**. edit-filepointer must call it to perform a real v3 file write, so the key cannot be renamed.
- **Resolution:** Every retired **FilePointer field READ** (`filePointer.fileMetaIpnsName`, `.folderKeyEncrypted`, `.fileKeyEncrypted`, `.type`, `vaultKeyBlob.rootFolderKey`) was eliminated. The one remaining grep hit (`edit-filepointer.mts:196`) is the current-signature SDK parameter key — the plan's over-broad token happens to also match it. Grep is at **1 line**, down from the legacy model's many; the migration intent (no retired field access) is fully satisfied. JSON output keys were renamed `fileMetaIpnsName -> fileIpnsName` to avoid unnecessary matches (harness does not parse that key).

### Not needed

- **Shell harness unchanged** — the three helpers preserve their CLI args (`--api-url`, `--email`, `--file-name`, `--folder-name`, `--new-content`, `--folder-name`/`--new-name`) and JSON-stdout contract, so `test-round-trip.sh`, `test-cross-client-sync.sh`, and `test-move-content.ts` drive them without edits. No trivial arg change to `test-round-trip.sh` was required.

## Known Stubs

None. The helpers perform real node/v3 read/write round-trips against the live SDK types.

## Self-Check: PASSED

- Files created: `.planning/.../69-25-SUMMARY.md` (this file) — FOUND.
- Files modified: three `.mts` helpers + `tsconfig.scripts.json` — FOUND (committed in `10f0defdb`).
- Commit `10f0defdb` — present on branch `worktree-agent-a487920066a25bcd3`.
