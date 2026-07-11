---
created: 2026-07-11T00:00:00.000Z
title: TS accepts a CBOR-float ValidityType 0.0 that the Rust decoder rejects (integer-only) — parity gap
area: sdk-core-ipns
severity: low
source: Phase 75 crypto/privacy review (.planning/security/REVIEW-2026-07-11-phase75-parity.md, finding 4). Fixed the two MEDIUM parity gaps (duplicate map keys, leading-sign/fixed-width RFC3339) inline on the phase 75 branch; this LOW one is deferred because the clean fix needs CBOR-type introspection, not a decode flag.
files:
  - packages/sdk-core/src/ipns/index.ts
  - crates/core/src/ipns.rs
resolves_phase: null
---

## Problem

`resolveIpnsRecord` gates on `ValidityType === 0` after `cborDecode`. cborg
collapses a CBOR float `0.0` (major type 7) and a CBOR integer `0` (major type 0)
to the same JS `0`, so a signed record encoding `ValidityType` as float-0.0 passes
the TS gate. The Rust decoder (`crates/core/src/ipns.rs` `decode_ipns_cbor_validity`)
requires a CBOR **Integer** major type and rejects the float. Net: a split-brain
where TS accepts a record Rust rejects.

Severity is LOW because the divergence is benign-direction: the only float that
slips through the `!== 0` gate is exactly `0.0`, which semantically still means
`ValidityType 0` (EOL) — the value we accept anyway. A non-zero float (e.g. `1.5`)
already fails `!== 0`. So TS's extra acceptance does not admit a record with a
different validity semantics; it only diverges from Rust on the encoding's major
type. Still worth closing for true cross-language parity (the phase's goal).

## Fix

`Number.isInteger()` does NOT distinguish 0.0 from 0 (both are `0`), so the gate
needs CBOR-type-level information. Options:

- Decode `ValidityType` via cborg's low-level token/`Type` API (or a targeted
  `tags`/typed decode) and reject any non-integer major type for that field, OR
- Re-encode the decoded ValidityType and assert it round-trips to the canonical
  integer encoding, OR
- Pre-scan the CBOR for the ValidityType entry's major type before the high-level
  decode.

Add a shared vector (or a TS unit test with hand-crafted float-0.0 CBOR bytes,
mirroring the duplicate-map-key test added in phase 75) that locks both sides to
reject a float-encoded ValidityType.
