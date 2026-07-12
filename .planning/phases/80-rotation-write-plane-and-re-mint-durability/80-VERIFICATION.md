---
phase: 80
slug: rotation-write-plane-and-re-mint-durability
status: PASS
verified: 2026-07-12
---

# Phase 80 — Verification

## Verdict: PASS

All three success criteria delivered and verified, plus a HIGH-severity
pin-durability gap (surfaced during ship review) closed.

## Success criteria

1. **D-01 — rotation republish no longer emits `write_sealed: None`.** FUSE
   rotation adapter reconstructs `NodeWriteBody` from the InodeTable and re-seals
   at the new generation; `replay::recover_signing_seed` succeeds on the
   reconstructed body. Verified by `rotation_reconstructed_write_sealed_recovers_signing_seed`
   and the full fuse suite (130 passed).
2. **D-02/D-03 — verified recipient binding + `/shares/sent` cached once per
   rotation.** Three-consumer fail-closed pin verification (Rust/TS/web); sent
   shares cached per rotation job. Verified by SDK-E2E share suites (106/106) and
   sdk-core rotation/grant-remint tests.
3. **D-04 — TS `rotatedNodes` defensive 32-byte copy.** Confirmed non-aliased in
   `rotation/engine.ts`; regression test asserts non-aliasing with
   `parentNewReadKey`.

## Ship-review additions

- **FLAG 1** (`replay.rs::fetch_splice_publish_parent` empty pins): real
  durability gap, FIXED (`3e3ec2a3d`).
- **HIGH — routine reseals dropped pins** (crypto review + CodeRabbit): FIXED
  across all routine paths (`ddb7082e6`) with Rust + TS regression tests.
- **CodeRabbit — `addRecipientPubkeyPin` missing ROT-07 reconcile**: FIXED.
- **FLAG 2** (winfsp): updated by inspection; confirmed via CI Windows job.

## Gate evidence

| Gate | Result |
|------|--------|
| Rust `cipherbox-fuse` (fuse) | 130 passed, 0 failed |
| SDK-E2E (client→API IPNS round-trip, TEE up) | 106 passed / 16 files |
| sdk unit | 423 passed / 3 skipped |
| sdk-core unit | 417 passed |
| core unit (incl. node-codec KAT) | 204 passed |
| TS client-chain rebuild (typecheck) | clean |

See `.planning/security/REVIEW-80.md` for the crypto/security review dispositions.
