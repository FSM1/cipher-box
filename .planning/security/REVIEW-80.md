# Phase 80 — Security & Crypto Review

**Date:** 2026-07-12
**Scope:** `git diff origin/main...HEAD` (rotation write-plane + re-mint durability; D-03 recipient-pubkey pinning).
**Passes:** crypto/privacy review, general security vulnerability sweep, CodeRabbit CLI.

## Verdict on D-03 (the crux)

The three-consumer fail-closed recipient-pin binding (Rust re-mint, TS re-mint,
web upgrade/reconcile) is **cryptographically sound** against the
substituted-relay-pubkey threat, conditional on the pins being present at
re-mint time:

- Every consumer verifies the relay-fed `recipientPublicKey` against the
  owner-sealed pin list read from an owner-authoritative source (Rust
  `InodeTable` cache populated from the unsealed write-body; TS/web the sealed
  write-body itself) — never from the server share record.
- The compare is raw-byte equality (Rust `pin == recipient_public_key`; TS
  length-guarded XOR `bytesEqual`). No loose/substring compare.
- A missing/empty pin on a surviving grant is a HARD fail everywhere (D-03e); no
  TOFU/backfill/legacy path. The wrap uses the relay pubkey only AFTER the
  byte-equality assertion, so it is equivalent to wrapping to the pin.
- `recipientPins` lives inside the AES-256-GCM–sealed write-body (server-opaque);
  the seal AAD (ROLE_BODY 0x01) still binds id/kind/generation. Frozen empty-pin
  KAT `seal_vectors[0]` byte-preserved; new `seal_vectors[1]` locks the
  non-empty path across Rust/TS.
- D-04 defensive copy of `rotatedNodes[].readKey` confirmed non-aliased (Rust
  `Zeroizing` clone; TS `new Uint8Array(...)`), so a future zeroize of
  `parentNewReadKey` cannot zero the returned key.

## Findings & dispositions

### HIGH — Routine write-body reseals dropped recipientPins — FIXED

The pin preservation wired into rotation-republish + journal-replay parent
re-splice was NOT wired into the routine mutation reseal paths
(`build_folder_metadata`, `publish_file_node`, and the TS `client.ts` publish
sites + `adoptPublishedFolderState`), so an ordinary write to a shared
folder/file republished it pin-less → later re-mint hard fail-closed (D-03e),
defeating revocation/rotation by ordinary usage. Independently surfaced by the
crypto review and CodeRabbit. **Fixed** in commit `ddb7082e6` across all routine
paths with Rust + TS regression tests; SDK-E2E stays 106/106.

FLAG 1 (`replay.rs::fetch_splice_publish_parent` empty pins) was the same class,
fixed earlier in commit `3e3ec2a3d`.

### MEDIUM — Pin lifecycle (pruning-on-revoke, growth, atomic issuance) — TODO

Pins are never pruned on revoke (a malicious relay could re-inject a
revoked-but-still-pinned recipient — a defense-in-depth gap, since revocation
already trusts relay grant-row honesty), grow unbounded (O(n²) union, never
pruned), and issuance is non-atomic (share row created before the pin CAS-write;
a failed pin-write strands an unpinned share that blocks whole-node rotation).
All fail-closed-safe (no key leak). Deferred to
`.planning/todos/pending/2026-07-12-recipient-pin-lifecycle-hardening.md`.

### CodeRabbit — `addRecipientPubkeyPin` missing reconcile-before-publish — FIXED

The pin-issuance publish skipped the ROT-07 durable anti-rollback
`reconcileFolderSequence` gate every other publish path uses. **Fixed** in
`ddb7082e6`.

### Dismissed (nits / no material impact)

- Pin domain type `string[]` (base64) vs `Uint8Array[]` (CodeRabbit): style
  refactor across the whole pin API, internally consistent (Rust `Vec<Vec<u8>>`,
  TS base64 wire), no correctness impact.
- `decode.ts` base64 validation of pins (CodeRabbit minor): input is
  AEAD-authenticated (relay cannot inject), fails safely at compare.
- `wb_bytes` not zeroized in `reconstruct_write_body` (security L3): mirrors the
  accepted `build_folder_metadata` pattern; freed-not-zeroed residue, low value.
- "compressed" vs uncompressed pin comment (I4): doc-only; raw-byte compare works
  regardless of encoding.

## Gate results

- Rust `cipherbox-fuse` (fuse): 130 passed.
- SDK-E2E (client→API IPNS round-trip, TEE worker up): 106/106.
- sdk unit: 423 passed / 3 skipped; sdk-core: 417; core (incl. KAT): 204.

winfsp Windows sites updated by inspection only (macOS/CI split) — confirmed via
the CI `Cargo Check & Test (Windows)` job on the PR.
