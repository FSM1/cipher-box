---
created: 2026-06-24
title: Tighten TS resolve Validity timestamp parsing for Rust parity
area: sdk-core
files:
  - packages/sdk-core/src/ipns/index.ts
resolves_phase: 75
---

## Problem

The TS resolve-side EOL/expiry check (`packages/sdk-core/src/ipns/index.ts` ~line 292-304) parses the CBOR `Validity` timestamp with `new Date(validityStr).getTime()`, which accepts many non-canonical formats. After Phase 60 the Rust verifier's `parse_rfc3339_to_unix_secs` was hardened to strictly reject malformed/impossible timestamps (trailing components, impossible calendar dates). The TS side is now looser than Rust on timestamp validity, a minor cross-layer parity gap.

Surfaced by CodeRabbit during the Phase 60 ship review (finding F13). Note: the finding's other half — requiring a non-zero `ValidityType` — was rejected as a **false positive / parity-breaking** (the Rust verifier never reads `ValidityType`, so enforcing it in TS would make TS *stricter* than Rust). Only the timestamp-strictness half is captured here, and it is deferred (low severity; the Ed25519 signature already covers the CBOR `Validity`, so a conformant signer always embeds a canonical timestamp).

## Solution

Replace the loose `new Date(...)` parse with strict RFC3339Nano-compatible validation (mirror the Rust parser: reject trailing date/time components and impossible calendar dates), keeping the existing 5-minute skew buffer and expiry comparison. Do **not** add ValidityType enforcement (would break Rust/TS parity). Add a cross-language test vector or sdk-core unit test pinning the malformed-timestamp cases.
