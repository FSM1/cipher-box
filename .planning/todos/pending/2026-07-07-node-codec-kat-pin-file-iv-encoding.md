---
created: 2026-07-07T00:00:00.000Z
title: Cross-language node-codec KAT does not pin the file_iv string ENCODING (hex vs base64)
area: crypto-kat-parity
severity: high
source: Phase 69 ship — desktop-e2e "Decryption failed" root cause (d07-write-plane-pairing.md, second bug); 2026-07-07
files:
  - tests/vectors/node-codec.json
  - tests/vectors/crypto/node-aad.json
  - crates/core/tests/node_codec_vectors.rs
  - packages/core (TS KAT generator/consumer)
---

## Problem

The whole node/v3 desktop cross-client read path shipped broken because the Rust
mount published `NodeContent.file_iv` as **hex** while the TS/web read chain
consumes it as **base64** (`base64ToBytes(fileIv)`). A TS reader decoded the mount's
24-char hex IV as base64 → 18 wrong bytes → AES-GCM tag failure → "Decryption
failed" on EVERY cross-language content read. Local mount reads passed (the mount
hex-decoded its own IV, self-consistent), so 476 unit tests + the KAT were all green.

**Why the KAT missed it:** `tests/vectors/node-codec.json` treats `file_iv` as an
opaque string, and its sample value `000102030405060708090a0b` is *coincidentally
valid as BOTH hex and base64*. So neither the Rust nor TS KAT consumer could tell
the two encodings apart — the vector round-trips regardless of which encoding the
implementation uses. The cross-language KAT is supposed to be exactly the guardrail
that prevents a Rust↔TS wire divergence like this.

Fixed the divergence (mount → base64) in the ship, but the KAT blind spot remains.

## Fix

1. Change the `file_iv` sample in `tests/vectors/node-codec.json` (and any
   `node-aad.json` seal vector carrying an IV) to a value that is **valid in exactly
   one encoding** — e.g. a base64 string containing a character outside `[0-9a-f]`
   (like `+`, `/`, or an uppercase letter) so a hex decoder rejects it, or whose
   base64-decoded bytes differ in length from its hex-decoded bytes. This forces
   both the Rust and TS KAT consumers to agree the field is base64.
2. Regenerate the KAT from the canonical generator so Rust and TS stay byte-identical,
   and confirm `crates/core/tests/node_codec_vectors.rs` + the TS KAT test both pass.
3. Consider a general rule: any KAT string field that carries encoded bytes must use
   a sample value that is unambiguous about its encoding.

## Acceptance

A Rust or TS implementation that (re)introduces a hex `file_iv` fails the
cross-language node-codec KAT. The node/v3 desktop-e2e cross-client read stays green.
