# 69 — node/v3 ROOT-KEY Lifecycle: Web (TS) vs Desktop (Rust), and Wiring the Real Recovery

Read-only research. Goal: replace the desktop placeholder root-key bridge
(`root_read_key = root_folder_key[..32]`, `root_write_key = root_read_key ^ 0xA5`)
with the REAL node/v3 root read/write keys the web persists, so desktop-e2e can
exercise a real vault round-trip.

## TL;DR

- **The web already has a fully-wired node/v3 two-key root model.** The desktop
  comments claiming "the v2.0 client runtime that recovers them is stubbed — phase 63"
  (`fuse/mod.rs:184-191`, `commands/vault.rs:11-18`) are **STALE**. Web PRs after
  phase 63 (#578, 69-20) shipped it.
- **Real model:** at registration the web generates **two independent random 32-byte
  keys** `rootReadKey` + `rootWriteKey` (NOT derived from anything), ECIES-wraps both
  under the user's secp256k1 public key, packs them into a **vault blob v3**
  (`0x03 | u16(readLen) | ECIES(readKey) | u16(writeLen) | ECIES(writeKey)`), uploads
  it to IPFS, and publishes it at the **HKDF-derived vault-key IPNS name**. The root
  **Ed25519 IPNS keypair is HKDF-derived** (deterministic, recomputable — NOT in the
  blob). The API DB is zero-knowledge (only `owner_public_key` + `root_ipns_name`).
- **The gap:** the desktop is still on the **legacy v2 single-key** model. It stores a
  `root_folder_key` (one random key) in a **v2 blob**, and fabricates the node/v3
  read/write keys with the `^ 0xA5` bridge. Rust `crates/core/src/vault_blob.rs` has
  **only v2**; `KeyState` has only `root_folder_key`. A web-created v3 vault is
  literally unreadable by the desktop today (`fetch_and_decrypt_vault` errors
  "Vault key blob is not v2 format", `vault.rs:377-379`), and vice-versa.
- **Recommended wiring:** port the web v3 model to Rust verbatim (option **a** — desktop
  reads/writes the SAME persisted v3 blob). The frozen cross-language KAT
  `tests/vectors/vault-v3-blob.json` already exists for exactly this. ~5 plans.
- **Desktop-e2e after wiring:** FUSE-local I/O tests pass immediately; the API
  round-trip verifier (`verify-filepointer.mts`) needs a `rootFolderKey → rootReadKey`
  fix. Full local stack (Postgres/api/Kubo/Redis/mock-ipns-routing/FUSE driver), no
  docker, dispatch-gated CI, runnable locally.

---

## Q1 — Web/TS node/v3 root-key model (generation, persistence, wrapping)

**Generation** — `packages/core/src/vault/init.ts:43` `initializeVault(userPrivateKey)`:

- `rootReadKey = generateFileKey()` — random 32 bytes (`init.ts:45`)
- `rootWriteKey = generateFileKey()` — random 32 bytes (`init.ts:46`)
- Both are **independent random keys**, explicitly NOT derived from each other or from
  the Ed25519 key (`types.ts:18-19`, `init.ts:8-9`).
- `rootIpnsKeypair = deriveVaultIpnsKeypair(userPrivateKey)` — **HKDF-derived,
  deterministic** (`init.ts:49`; HKDF info `"cipherbox-vault-ipns-v1"`,
  `packages/crypto/src/vault/derive-ipns.ts:44`).

For comparison, subfolder minting (`packages/sdk-core/src/folder/registration.ts:46`
`createSubfolder`) generates a fresh random Ed25519 keypair + random readKey/writeKey
per child (`registration.ts:60-67`). The confusingly-named return fields `rootReadKey`/
`rootWriteKey` (`registration.ts:54-55,127-134`) are per-*node* keys, not the vault root.
The vault ROOT specifically uses the `vault/init.ts` path above.

**Persistence** — three distinct sinks (`apps/web/src/hooks/useAuth.ts:179-239`,
new-user branch):

1. **Recoverable root keys → ECIES v3 blob on IPFS/IPNS.**
   - `encryptVaultKeys(vault, userPublicKey)` (`init.ts:79`) ECIES-wraps `rootReadKey`
     and `rootWriteKey` under the user's secp256k1 **public** key via `wrapKey`
     (`init.ts:84-85`; ECIES primitive `packages/crypto/src/ecies/encrypt.ts:26`,
     eciesjs, output `ephemeral_pubkey || ciphertext || tag`).
   - `serializeVaultBlobV3(encRead, encWrite)` (`packages/core/src/vault/blob.ts:33`)
     → `0x03 | u16_BE(readLen) | ECIES(readKey) | u16_BE(writeLen) | ECIES(writeKey)`.
     **The blob deliberately omits the IPNS private key.**
   - Uploaded to IPFS and published at seq `1n` to the **dedicated vault-key IPNS name**
     `deriveVaultKeyIpnsKeypair(userPrivateKey)` (HKDF info
     `"cipherbox-vault-key-ipns-v1"`, `packages/crypto/src/vault/derive-ipns.ts:89`;
     `useAuth.ts:185,196-203`).

2. **Empty root Node → IPFS/IPNS at the root IPNS name.**
   - `publishEmptyRootNode(...)` (`packages/sdk-core/src/vault/index.ts:118`) seals an
     empty `schema:'node/v3'` root Node whose **writeBody carries
     `ipnsPrivateKey: rootIpnsKeypair.privateKey`** (`index.ts:161-172`) under
     `rootReadKey`/`rootWriteKey`, publishes at seq `1n`.

3. **API DB registration (metadata only, zero-knowledge).**
   - `POST /vault/init` with `{ ownerPublicKey, rootIpnsName }` only
     (`apps/api/src/vault/vault.controller.ts:37` → `vault.service.ts:64`).
   - `vaults` table (`apps/api/src/vault/entities/vault.entity.ts`): `owner_id`,
     `owner_public_key` (bytea), `root_ipns_name` (varchar), `is_byo_user`, timestamps.
     **No wrapped-key columns exist** — confirmed, the server never sees key material.

**Answer to the sub-questions:** root read/write keys are **random** (not derived);
root IPNS key is **HKDF-derived**. Persistence is **client-side, in an IPFS/IPNS vault
blob v3** (not a DB endpoint). Wrapping is **ECIES under the user's secp256k1 public key**.

---

## Q2 — Web recovery/login

Existing-vault branch `apps/web/src/hooks/useAuth.ts:150-178`:

1. `GET /vault` → `{ ownerPublicKey, rootIpnsName, id, teeKeys }` (`vault.controller.ts:112`).
2. Recompute vault-key IPNS name: `deriveVaultKeyIpnsKeypair(userPrivateKey)` (`useAuth.ts:157`).
3. `resolveIpnsRecord(...)` + `fetchFromIpfs(cid)` → blob bytes (`useAuth.ts:159-162`).
4. `deserializeVaultBlobV3(blob)` → `{ encryptedRootReadKey, encryptedRootWriteKey }`
   (`blob.ts:87`; `useAuth.ts:165`).
5. **ECIES-unwrap under the user PRIVATE key**: `unwrapKey(encryptedRootReadKey, privateKey)`
   and same for write (`useAuth.ts:166-167`; `packages/crypto/src/ecies/decrypt.ts:23`).
6. **Re-derive** the root IPNS keypair via HKDF — never fetched/unwrapped:
   `deriveVaultIpnsKeypair(userPrivateKey)` (`useAuth.ts:170`).
7. `setVaultKeys({ rootReadKey, rootWriteKey, rootIpnsKeypair, rootIpnsName, vaultId })`
   (`useAuth.ts:172-178`).

**Runtime KeyState shape** — `useVaultStore` / `VaultState`
(`apps/web/src/stores/vault.store.ts:12-36`): `rootReadKey: Uint8Array|null`,
`rootWriteKey: Uint8Array|null`, `rootIpnsKeypair: {publicKey, privateKey}|null`,
`rootIpnsName: string|null`, plus `vaultId`/`isInitialized`. Zeroized on logout
(`vault.store.ts:74-103`). These bootstrap the SDK via `initSdkClient(...)`
(`useAuth.ts:321-351`).

Note: `decryptVaultKeys` (`init.ts:119`, which unwraps an `encryptedIpnsPrivateKey`)
exists but is **not** on the web login path — the live path uses the v3 blob (read+write
only) + HKDF re-derivation of the IPNS key. Wiring status: **fully wired, no stubs**
(grep of `useAuth.ts`, `vault.store.ts`, `sdk-provider.ts`, `sdk-core/src/vault/index.ts`
for "not implemented / phase 63 stub / TODO / FIXME" = zero hits; the lone "phase 63"
string at `folder.store.ts:20` is descriptive).

---

## Q3 — Desktop Rust current state (legacy)

**AppState / KeyState** (`apps/desktop/src-tauri/src/state.rs`,
`crates/sdk/src/state.rs:37-69`) — SINGLE-key legacy model:

- `root_folder_key: RwLock<Option<Zeroizing<Vec<u8>>>>` (one 32-byte AES key)
- `root_ipns_name: RwLock<Option<String>>`
- `root_ipns_private_key: RwLock<Option<Vec<u8>>>`
- **No `root_read_key` / `root_write_key` fields.**

**Registration** — `apps/desktop/src-tauri/src/commands/vault.rs:154` `initialize_vault`:

- Generates ONE random `root_folder_key` (32 bytes, `vault.rs:156`).
- HKDF-derives the root IPNS keypair (`derive_vault_ipns_keypair`, `vault.rs:173`) and
  the vault-key IPNS keypair (`derive_vault_key_ipns_keypair`, `vault.rs:178`).
- ECIES-wraps `root_folder_key` and packs it into a **v2 blob**
  (`serialize_vault_blob_v2`, `vault.rs:183,192`), publishes to the vault-key IPNS.
- Builds the empty root node with **bridge keys** via `derive_root_node_keys`
  (`vault.rs:19-39`: `read = root_folder_key[..32]`; `write = read ^ 0xA5`) →
  `build_empty_root_published_node` (`vault.rs:52-81`).
- `POST /vault/init { owner_public_key, root_ipns_name }` (`vault.rs:280-290`).

**Recovery** — `vault.rs:307` `fetch_and_decrypt_vault`:

- `GET /vault`, resolve vault-key IPNS, fetch blob.
- **Requires v2** (`detect_blob_version != 2 → error`, `vault.rs:377-379`),
  `deserialize_vault_blob_v2` → ECIES-unwrap → `root_folder_key` (`vault.rs:380-387`).
- Re-derives root IPNS key via HKDF (`vault.rs:344,390`). Stores `root_folder_key`,
  `root_ipns_private_key`, `root_ipns_name`, `tee_keys` into KeyState.

**Mount** — `apps/desktop/src-tauri/src/fuse/mod.rs:80` `mount_filesystem` takes
`root_folder_key` and re-computes the SAME `^ 0xA5` bridge inline (`mod.rs:192-205`)
before seeding the root inode (`mod.rs:207-215`) and threading the keys into
`prepopulate_filesystem` (`mod.rs:226-234`) and `replay_for_vault` (`mod.rs:287-301`).
`post_auth_finalize` (`commands/auth.rs:198-244`) reads `root_folder_key` from state and
passes it into the mount.

**What it recovers TODAY:** `root_folder_key` (one legacy key) + HKDF root IPNS key.
**What it MUST additionally recover for node/v3:** the two independent random
`rootReadKey`/`rootWriteKey` from a **v3 blob**. There is no Rust equivalent of the web
v3 vault codec — the desktop hits the same `/vault/init` + `/vault` API and publishes its
own blob, so **only the client-side blob format + KeyState fields must change**, not the
API.

---

## Q4 — The gap + minimal wiring

### Precise gap

| Concern | Web (TS) — canonical | Desktop (Rust) — today |
|---|---|---|
| Root keys | 2 independent random (readKey, writeKey) | 1 random `root_folder_key`, fake read/write via `^0xA5` |
| Blob format | v3 (`0x03` two-key) `packages/core/src/vault/blob.ts` | v2 (`0x02` one-key) `crates/core/src/vault_blob.rs` (v3 NOT implemented) |
| KeyState | `rootReadKey`,`rootWriteKey`,`rootIpnsKeypair` | `root_folder_key`,`root_ipns_private_key` (no read/write) |
| Root IPNS key | HKDF `cipherbox-vault-ipns-v1` | HKDF `cipherbox-vault-ipns-v1` (already matches) |
| Interop | — | v3 vault ↔ desktop **mutually unreadable** |

The Rust root IPNS HKDF derivation is already byte-identical to TS (verified by
`crates/crypto/tests/cross_language.rs:200-217`), so **the IPNS key is already correct**.
The ONLY missing piece is the two symmetric root keys and their v3 blob envelope.

### Recommended approach: (a) desktop reads/writes the SAME persisted v3 blob

Mirror the web v3 model in Rust verbatim. Rationale:

- **The web keys are RANDOM** → they cannot be HKDF-re-derived, so option (c)
  deterministic derivation is impossible without diverging from web. Rejected.
- Option (b) desktop-only registration would leave web-created and desktop-created
  vaults mutually unreadable — the opposite of what real cross-client e2e needs. Rejected.
- Option (a) makes a vault created on either client openable on the other, matches the
  zero-knowledge ECIES contract, and reuses the **already-frozen KAT**
  `tests/vectors/vault-v3-blob.json` (note in-file: "freeze the v3 envelope byte-layout
  for Phase-69 Rust `cross_language.rs` to assert the same bytes"). This is the
  intended design — the vector was shipped in #578 waiting for the Rust port.

### Concrete change set

1. **`crates/core/src/vault_blob.rs`** — add `BLOB_V3_VERSION=0x03`,
   `serialize_vault_blob_v3(enc_read, enc_write)`, `deserialize_vault_blob_v3(blob) ->
   (read, write)` byte-matching `packages/core/src/vault/blob.ts`. (Optionally retire v2 —
   web already hard-cut v2 in #578; a v2-detect fallback could stay for a migration window.)
2. **`crates/sdk/src/state.rs` (`KeyState`)** — add
   `root_read_key: RwLock<Option<Zeroizing<Vec<u8>>>>` and
   `root_write_key: RwLock<Option<Zeroizing<Vec<u8>>>>` (zeroize both in `clear()`).
   Keep `root_folder_key` only if a v2 fallback is retained, else replace it.
3. **`apps/desktop/src-tauri/src/commands/vault.rs`**
   - `initialize_vault`: generate TWO random 32-byte keys; ECIES-wrap both; build a v3
     blob; publish to the vault-key IPNS; build the empty root node with THOSE keys.
     **Delete `derive_root_node_keys` (the `^0xA5` bridge, `vault.rs:19-39`).**
   - `fetch_and_decrypt_vault`: deserialize v3 blob → unwrap both → store into
     `root_read_key`/`root_write_key`. Root IPNS key stays HKDF-derived.
4. **`apps/desktop/src-tauri/src/commands/auth.rs` (`post_auth_finalize`)** — read
   `root_read_key`/`root_write_key` from state, pass them into `mount_filesystem`.
5. **`apps/desktop/src-tauri/src/fuse/mod.rs` (`mount_filesystem`)** — accept
   `root_read_key`/`root_write_key` params; **delete the inline `^0xA5` bridge
   (`mod.rs:179-205`)**. `prepopulate.rs` and `replay_for_vault` already take
   `&root_read_key`/`&root_write_key` (`mod.rs:226-234,287-301`), so downstream is ready.

The Rust seal path is already correct: `build_empty_root_published_node` (`vault.rs:52`)
seals both bodies via `seal_published_node(.., Some(&write_body))` and is unit-tested
(`vault.rs:408-491`); it just needs to be fed real random keys.

---

## Q5 — Desktop-e2e harness

**Location / shape:** `tests/desktop-e2e/` (package `@cipherbox/desktop-e2e`) — shell +
PowerShell scripts with tsx-run `.ts`/`.mts` helpers (NOT Playwright/tauri-driver).
- Orchestrator: `tests/desktop-e2e/scripts/run-all.sh` (+ `.ps1`).
- FUSE I/O: `test-fuse-operations.sh` (create/read/mkdir/overwrite/256KB SHA-256/rename/
  move/delete against `$HOME/CipherBox`).
- API round-trip: `test-round-trip.sh` — writes into the mount, polls `GET /vault`, runs
  `packages/sdk-core/scripts/verify-filepointer.mts` (resolves FilePointer → per-file IPNS
  → downloads + decrypts, asserts equality), re-runs to simulate a fresh client.
- Shared auth helper: `tests/e2e-helpers/auth.ts` / `types.ts`.

**Web3Auth bypass (`--dev-key` + `/auth/test-login`):** CI launches the debug binary
`"$BINARY" --dev-key $DEV_KEY &` (`desktop-e2e.yml`). Rust parses `--dev-key`
(`main.rs:68-94`) → `AppState.dev_key`, exposed via `get_dev_key` (`commands/debug.rs:20`);
frontend `main.ts:573-612` POSTs `/auth/test-login {email:'dev-key@cipherbox.local',
secret: VITE_TEST_LOGIN_SECRET}`. **Critically the keypair comes from the server's
test-login `privateKeyHex`, NOT the CLI dev key** (`main.ts:566-612`) — the CLI value only
flags headless mode. Matches the `project-headless-desktop-fuse-uat` recipe.

**Stack required (full LOCAL, provisioned natively in `.github/workflows/desktop-e2e.yml`,
no docker):** PostgreSQL 16 (`cipherbox_test` + migrations), `apps/api` built + run on
`:3000` (health-gated), **Kubo/IPFS v0.34.0** (`:5001`/`:8080`, `IPFS_PROVIDER=local`),
**Redis** `:6379`, **mock-ipns-routing** `:3001` (`tools/mock-ipns-routing`), FUSE driver
(FUSE-T macOS / libfuse3 Linux / WinFsp 2.1 Windows), frontend built with
`VITE_TEST_LOGIN_SECRET=e2e-test-secret-ci-only` (must match API `TEST_LOGIN_SECRET`).

**CI:** reusable `desktop-e2e.yml` (job `desktop-e2e`), orchestrated by `ci-e2e.yml`
("CI E2E Tests"), **dispatch-gated** — `push:[main]` + `workflow_dispatch` only, desktop
job runs `if desktop-changed || workflow_dispatch` (`ci-e2e.yml:87`). No PR trigger
(matches `project-desktop-e2e-dispatch-gated`).

**node/v3 readiness:** The SDK is already v3 (`packages/sdk-core/src/vault/index.ts:1-99`,
`loadVaultKeyBlob` returns `{rootReadKey, rootWriteKey, ipnsName}`). **But the round-trip
verifier is stale:** `verify-filepointer.mts:71,85` reads `vaultKeyBlob.rootFolderKey`
(retired in v3) and passes it as `folderKey` — `undefined` at runtime (tsx does no
typecheck). So today the **FUSE-local I/O tests are meaningful, but the API round-trip /
content-decrypt path does NOT validate a real v3 vault** as written. Corroborated by
`.planning/todos/pending/2026-07-03-reenable-quarantined-sdk-e2e-suites-on-v3.md`
(sibling sdk-e2e suites quarantined for the same legacy `rootFolderKey`/no-writeKey
assumption). A small verifier fix (`rootFolderKey → rootReadKey`, thread `rootWriteKey`)
is required for the round-trip to meaningfully exercise the node/v3 flip.

---

## Q6 — Cross-language KAT (byte-identical TS ↔ Rust)

Two derivations must stay byte-identical:

1. **Vault blob v3 envelope** — frozen KAT `tests/vectors/vault-v3-blob.json`
   (`0x03 | u16(readLen) | ECIES(read) | u16(writeLen) | ECIES(write)`; read=`0xaa`+0..0x7f,
   write=`0xbb`+0..0x7f). TS side consumes it via
   `packages/core/src/__tests__/...vault-blob-vectors.test.ts` (from #578). **Rust side is
   MISSING** — the new `serialize/deserialize_vault_blob_v3` must add a
   `test_cross_platform_v3_vector` loading this JSON (mirroring the existing v2 vector
   test at `crates/core/src/vault_blob.rs:129-163`), or extend
   `crates/crypto/tests/cross_language.rs`.
2. **Root IPNS keypair HKDF** — already KAT-locked: `tests/vectors/crypto/hkdf.json` +
   `crates/crypto/tests/cross_language.rs:200-217` (`cipherbox-vault-ipns-v1`,
   `cipherbox-vault-key-ipns-v1`). No change needed; the desktop already derives the
   right IPNS name/key.
3. **Node seal / codec** — already cross-language KAT'd
   (`tests/vectors/crypto/node-aad.json`, `tests/vectors/node-codec.json` via
   `crates/core/tests/node_seal_vectors.rs`, `node_codec_vectors.rs`). The root node the
   desktop emits already round-trips (`vault.rs:408-491`). No change needed.

ECIES itself is non-deterministic (ephemeral key) so it is not byte-frozen; the v3 blob
KAT uses synthetic ECIES stand-ins to freeze only the ENVELOPE layout — the Rust port
must match that layout exactly.

---

## Estimated plan breakdown

| # | Plan | Files | Notes |
|---|---|---|---|
| 1 | Rust vault blob v3 codec + cross-language KAT | `crates/core/src/vault_blob.rs`, load `tests/vectors/vault-v3-blob.json` | Pure/no-IO; TDD against the frozen vector. Decide v2 retire vs. keep detect-fallback. |
| 2 | `KeyState` two-key fields | `crates/sdk/src/state.rs` (+ its unit tests) | Add `root_read_key`/`root_write_key` (Zeroizing), zero in `clear()`. |
| 3 | Desktop vault init + recovery → v3 | `apps/desktop/src-tauri/src/commands/vault.rs` | Generate 2 random keys, wrap+serialize v3, publish; deserialize v3 on fetch; delete `derive_root_node_keys` bridge. |
| 4 | Mount wiring: drop the `^0xA5` bridge | `apps/desktop/src-tauri/src/commands/auth.rs`, `apps/desktop/src-tauri/src/fuse/mod.rs` | Thread real `root_read_key`/`root_write_key` from state into `mount_filesystem`; remove `mod.rs:179-205`. prepopulate/replay already accept them. |
| 5 | Desktop-e2e verifier alignment + run | `packages/sdk-core/scripts/verify-filepointer.mts` (+ siblings `edit-filepointer.mts`, `rename-folder.mts`), `test-round-trip.sh` if needed | `rootFolderKey → rootReadKey`, thread `rootWriteKey`. Then run local stack. |

Plans 1–2 are foundation (parallelizable). 3 depends on 1+2. 4 depends on 3. 5 depends on
4 and validates end-to-end. Consider a shared-write / cross-client interop assertion in
plan 5 (create vault on web, open on desktop — or vice versa — proving option (a)).

**Is desktop-e2e runnable after?** Yes. FUSE-local I/O passes as soon as plans 3–4 land
(a desktop-created v3 vault mounts and round-trips locally). The API round-trip /
content-decrypt assertions need plan 5's verifier fix to be meaningful. Stack: the full
LOCAL stack from `desktop-e2e.yml` — Postgres 16, `apps/api`, Kubo v0.34, Redis,
mock-ipns-routing, plus the platform FUSE driver — provisioned natively (no docker),
dispatch-gated in CI, and runnable locally via the `--dev-key` headless UAT recipe.
