---
phase: 55-large-source-file-refactor
requirement: HARD-06
title: Security sign-off — Large Source-File Refactor
status: SECURED
threats_open: 0
reviewer: security-tester
base_commit: b57a9c5de
head_commit: 91eb0fe4f
date: 2026-06-21
verdict: SECURED — no security-relevant behavior change
---

# Phase 55 Security Review — Large Source-File Refactor

## Scope

Phase 55 is a pure structural refactor (requirement HARD-06): large source files
were split into smaller modules. No behavior change is intended. This review
verifies that the security-relevant code MOVES preserved crypto and
key-handling behavior byte-for-byte (modulo location, visibility, and
fully-qualified module paths), and that no new threats were introduced.

Method: for each item the pre-refactor original was extracted via
`git show b57a9c5de:<old-path>` and diffed against the post-refactor code.
Donor files (the larger files code moved FROM) were checked for stray edits.
The fuse crate was compiled (`cargo check -p cipherbox-fuse --features fuse`,
clean) to authoritatively confirm no crypto call was orphaned by the dedup.

## Threat-Mitigation Table

A pure, behavior-identical move introduces no new attack surface: the same
bytes execute the same crypto with the same keys, only from a different file.
The table records the threats that COULD be introduced by a careless
"refactor" and confirms each is not present.

| #  | Potential refactor-introduced threat                              | Mitigation / Verification                                                                                                  | Status     |
| -- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ---------- |
| T1 | Altered crypto path (different algorithm/mode after move)          | ECIES unwrap/wrap, AES-CTR, AES-GCM calls diffed byte-for-byte; only fully-qualified module paths changed (same re-exports) | MITIGATED  |
| T2 | Weakened IPNS record validation (codec change)                    | `parseIpnsRecordBytes`/`parseCachedRecord`/`withCachedPublicKey` logic-identical; same `parseIpnsRecord` backing call       | MITIGATED  |
| T3 | Key material newly logged after extraction                        | Log sweep of all 6 changed files: no key value logged; only literal field names / config values                            | MITIGATED  |
| T4 | Broadened visibility exposing key-handling fns beyond the crate   | Widenings are `pub(crate)` only (load_vault_settings, resolve helpers); never `pub`; key-deriving fn stays crate-internal   | MITIGATED  |
| T5 | Lost zeroization (key copied/retained beyond original scope)      | Owner still holds `Zeroizing`; callees take `&[u8]` borrows; transient `[u8;32]` copies wrapped in `Zeroizing` (improved)   | MITIGATED  |
| T6 | Changed timeout affecting a security/availability invariant       | macOS 3s sync FUSE timeout vs 10s async kept distinct (sync wrapper left in each operations.rs); vault 10s timeout preserved | MITIGATED  |
| T7 | Unencrypted IPNS private key sent to server / TEE                 | `ecies::wrap_key(file_ipns_private_key, tee_key)` preserved; `encrypted_ipns_private_key` still TEE-wrapped before publish   | MITIGATED  |
| T8 | Dropped/orphaned crypto call during dedup                         | `cargo check -p cipherbox-fuse --features fuse` passes; removed-call gap fully explained by macOS+Windows dedup collapse     | MITIGATED  |
| T9 | privateKey persisted to localStorage/sessionStorage              | No code writes keys to web storage; only a pre-existing doc comment mentions Core Kit session restore                       | MITIGATED  |

Open threats: 0.

## Per-Item Verdicts

### Item 1 — `crates/fuse/src/content_ops.rs` (hoisted async helpers)

Verdict: PASS — behavior-identical.

- `fetch_and_decrypt_content_async` and `publish_file_metadata` were extracted
  from `operations.rs` (macOS) and `platform/windows/operations.rs` (Windows).
  The two base copies were already byte-identical (the Windows base already used
  the fully-qualified `ecies::`/`aes_ctr::`/`aes::` paths); the shared copy
  matches them exactly.
- Crypto preserved:
  - `cipherbox_crypto::ecies::unwrap_key` (== top-level `unwrap_key` re-export;
    verified in `crates/crypto/src/lib.rs:18`).
  - `cipherbox_crypto::aes_ctr::decrypt_aes_ctr` and
    `cipherbox_crypto::aes::decrypt_aes_gcm` (== re-exports at lib.rs:16-17).
  - `cipherbox_crypto::ecies::wrap_key` for TEE enrollment.
- IV/nonce handling unchanged: CTR expects 16-byte IV, GCM expects 12-byte IV,
  both length-checked exactly as before.
- Key material: `unwrap_key` returns `Zeroizing<Vec<u8>>`; folder/IPNS keys
  copied into `Zeroizing<[u8;32]>` via the preallocate-then-copy
  `zeroizing_32_from_slice` helper (no bare-array temporary). No key logged.
- The SYNCHRONOUS wrapper `fetch_and_decrypt_file_content` was intentionally
  NOT hoisted (A2 scope note in `content_ops.rs:6-15`): it uses different
  timeouts per platform (macOS private `NETWORK_TIMEOUT = 3s` vs Windows
  `crate::block_with_timeout = 10s`). Both sync wrappers were diffed against
  base and are byte-identical (`operations.rs:68-114`,
  `platform/windows/operations.rs:214-262`). The 3s/10s distinction is
  preserved (T6).

### Item 2 — `crates/fuse/src/publish.rs` (PublishCoordinator + sequence helpers)

Verdict: PASS — behavior-identical.

- `PublishQueueEntry`, `next_file_publish_sequence`, `PublishCoordinator`
  (+ `new`, `get_lock`, `resolve_sequence`, `resolve_sequence_strict`,
  `record_publish`, `get_cached`, `update_cache`), and the replay-classification
  helpers `resolve_ipns_for_replay` / `classify_resolve_outcome` moved from
  `lib.rs` unchanged.
- IPNS key / sequence handling identical: monotonic `max(resolved, cached)`,
  `update_cache` only advances, the `not found`/`404` substring contract for
  first-publish classification is byte-identical. The `#19` substring contract
  is now additionally pinned by a moved-alongside unit test.
- No key material is handled here (only `u64` sequence numbers and error
  strings). The two replay helpers widened from file-private to `pub(crate)`
  (required for cross-module calls post-split); not `pub`, no key exposure (T4).
- Re-exported from `lib.rs` as `publish::{PublishCoordinator, PublishQueueEntry,
  next_file_publish_sequence}`, preserving the `crate::PublishCoordinator` /
  `crate::next_file_publish_sequence` call paths the rest of the crate uses.
  No duplicate definitions remain in `lib.rs`.

### Item 3 — `apps/api/src/ipns/ipns-record.codec.ts` (IPNS record codec)

Verdict: PASS — record parsing/validation byte-identical.

- `parseIpnsRecordBytes`, `parseCachedRecord`, `withCachedPublicKey` extracted
  from `ipns.service.ts` (base lines 545-660) into a standalone module.
- Validation preserved exactly:
  - Same backing call `parseIpnsRecord(recordBytes)` from `@cipherbox/crypto`
    (signature/pubkey verification lives inside that lib call — unchanged).
  - Same CID regex `/\/ipfs\/([a-zA-Z0-9]+)/` and BAD_GATEWAY on mismatch.
  - Same `String(record.sequence ?? 0n)` sequence handling.
  - Same base64 encoding of `signatureV2`/`data`/`pubKey`.
  - `withCachedPublicKey` guard `result.pubKey || !result.signatureV2 ||
    !result.data || !publicKey` byte-identical — the condition that controls
    whether a cached pubKey is attached is unchanged.
  - `parseCachedRecord` keeps DB columns authoritative for cid/sequenceNumber
    and emits the same CID-mismatch warning.
  - Same error handling: rethrow `HttpException`, else throw BAD_GATEWAY.
- Only mechanical changes: `this.logger` became an injected `logger: Logger`
  parameter; inline type literals became the exported `IpnsRecordFields`
  interface (structurally identical). Call sites in `ipns.service.ts`
  (lines 465, 485, 488) pass the same arguments in the same order; no inline
  duplicate remains.

### Item 4 — Desktop key/credential handling

Verdict: PASS — no change to key/credential handling or auth flow.

- `commands/vault.rs::load_vault_settings` — body byte-identical to the base
  `auth.rs` version (derive vault-settings IPNS keypair via HKDF -> resolve ->
  fetch -> `ecies::unwrap_key` -> validate -> default on any failure). The
  "NOT AES-GCM -- vault settings use ECIES wrapKey" invariant and the 10s
  timeout are preserved. Visibility widened to `pub(crate)` only (for the
  cross-module call). Private key taken by `&[u8;32]` reference; logs only
  settings values, never the key.
- `commands/auth.rs::complete_auth_setup` — head (steps 1-6: token storage,
  JWT user-id extraction, Keychain storage, in-memory key storage, vault
  init/fetch, vault-settings load) byte-identical. The mount/sync/device-
  registry/window-teardown tail was factored into a new private
  `post_auth_finalize`. The factored tail is byte-identical; the private key is
  passed as `&Zeroizing<Vec<u8>>` (still zeroizing-wrapped, by reference, no
  extra copy). Device-registry spawn still wraps in `Zeroizing::new(...to_vec())`.
  `public_key_bytes.clone()` -> `.to_vec()` and `user_id.clone()` ->
  `.to_string()` are param-type artifacts producing identical values. The
  "Authentication complete" log moved to the end of `complete_auth_setup`,
  firing after the (now-extracted) tail returns Ok — same ordering. No key
  logged; no localStorage/sessionStorage write.
- `fuse/prepopulate.rs::prepopulate_filesystem` — normalizes the two
  structurally-parallel-but-not-byte-identical macOS and Windows inline blocks
  into one shared function (A3 note in the file). Both `fuse/mod.rs:181` and
  `fuse/windows/mod.rs:92` now call it. Crypto preserved:
  `decrypt_metadata_from_ipfs_public` (root + subfolder) and
  `decrypt_file_metadata_from_ipfs_public` (file pointers), same key arguments.
  Caller still owns `root_folder_key: Zeroizing<Vec<u8>>` and passes a borrow
  (`.as_slice()`); callee takes `&[u8]`, never takes ownership, and wraps its
  transient `[u8;32]` folder-key copies in `Zeroizing` at BOTH root and
  subfolder levels.

  Two intentional non-byte-identical normalizations, both security-neutral or
  security-positive (see Notes below).

## Notes — Intentional Normalizations in prepopulate.rs (not concerns)

These are deliberate convergences of the two base platform blocks, documented
in the file's A3 note. Neither weakens security.

1. Root file-pointer scoping (INFORMATIONAL — slight improvement). Both base
   blocks used the unscoped `get_unresolved_file_pointers()` at the root level;
   the shared function uses `get_unresolved_file_pointers_for_parent(ROOT_INO)`.
   At the call site only the root folder is populated, so both return the same
   set; the scoped variant additionally guards against ever decrypting a
   non-root pointer with the root folder key (its doc: "Avoids retrying
   root-level or other-folder pointers with the wrong folder key"). Wrong-key
   decrypt would fail gracefully either way, so no data exposure in either
   form; the scoped form strengthens key-to-folder binding.

2. Root folder-key zeroization (improvement over Windows base). The base
   Windows root block held the `[u8;32]` root folder key as a BARE array
   (un-zeroed); the base macOS block wrapped it in `Zeroizing`. The shared
   function wraps it in `Zeroizing` at the root level, so the Windows path now
   zeroizes a key copy it previously left on the stack. Strictly better; equal
   to the macOS baseline.

## CLAUDE.md Security-Rule Compliance

| Rule                                                              | Status |
| ---------------------------------------------------------------- | ------ |
| Never store `privateKey` in localStorage/sessionStorage           | PASS — no such writes introduced |
| Never log sensitive keys                                          | PASS — log sweep clean across all 6 files |
| Never send unencrypted keys to server                            | PASS — IPNS key TEE-wrapped before publish |
| Always use ECIES for key wrapping                                | PASS — `ecies::wrap_key`/`unwrap_key` preserved |
| Always use AES-256-GCM for content (CTR for legacy/large)        | PASS — `aes::decrypt_aes_gcm` / `aes_ctr::decrypt_aes_ctr` preserved |
| Server never sees plaintext or unencrypted keys                  | PASS — no client/server boundary change |
| Encrypt `ipnsPrivateKey` with TEE public key before republishing | PASS — `wrap_key(file_ipns_private_key, tee_key)` preserved |
| TEE decrypts IPNS keys in hardware only                          | PASS — TEE path untouched by this refactor |

## Conclusion

SECURED. All four security-relevant moves are behavior-preserving (byte-identical
modulo location, visibility widening to `pub(crate)`, and fully-qualified module
paths that resolve to the same re-exported crypto functions). The only deviations
from byte-identical are two intentional prepopulate normalizations, both
security-neutral or security-positive. No new threats introduced; 0 threats open.
