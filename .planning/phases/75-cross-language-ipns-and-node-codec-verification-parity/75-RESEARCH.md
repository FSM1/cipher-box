# Phase 75: Cross-Language IPNS and Node-Codec Verification Parity - Research

**Researched:** 2026-07-11
**Domain:** Rust↔TypeScript cross-language cryptographic verification parity (IPNS CBOR verify, node/v3 codec KAT, AAD UUID parsing)
**Confidence:** HIGH

## Summary

This phase closes four specific, already-diagnosed parity gaps between the Rust verifier (source of truth) and the TS verifier, each captured as a `resolves_phase: 75` todo. All four gaps were found by prior security/ship reviews (CodeRabbit on PR #555, the Phase 61 adversarial review, and the Phase 69 desktop-e2e incident) — this is not exploratory research, it is grounding the exact current code so the planner can write byte-precise tasks.

Two of the four gaps are genuinely two-sided (both languages must change in lockstep): ValidityType binding (currently BOTH sides ignore it — fixing only one breaks parity) and the UUID acceptance domain (TS is looser than Rust today). The other two are one-sided hardening: TS RFC3339 parsing must become as strict as Rust's already-hardened parser, and the node-codec KAT needs a new assertion path — not just a new sample value — because today's KAT never decodes `fileIv` to bytes on either side.

**Primary recommendation:** Implement all four as paired Rust+TS changes gated by new/extended shared JSON vectors, in this dependency order: (1) RFC3339 strictness in TS (self-contained, no cross-file coupling), (2) ValidityType binding (touches `decode_ipns_cbor_validity`'s signature, all 3 call sites, plus the vector classifier — do this after (1) since it also touches Validity parsing), (3) node-codec `fileIv` KAT hardening (add a real decode-and-compare assertion, not just a new sample), (4) UUID acceptance domain tightening to Option A (canonical-only) — verified safe because no test or call site in this repo relies on non-canonical `node_id`/`childId` forms.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| IPNS Validity/EOL parsing & expiry binding | SDK / Crypto-core (Rust `crates/api-client` + `crates/core`; TS `packages/sdk-core`) | — | Both are client-side verification chokepoints (`resolve_ipns_verified` / `resolveIpnsRecord`); no server/API involvement — the API just relays opaque signed bytes |
| Node-codec wire-format KAT (`fileIv` encoding) | Core codec (Rust `crates/core/src/node`; TS `packages/core/src/node`) | Content-decrypt call sites (`crates/fuse`, `packages/sdk-core`, `apps/web`) | The codec crate/package owns the wire *shape*; the KAT's job is to pin that shape so consumers never independently discover a mismatch (as happened in the Phase 69 incident) |
| AAD UUID acceptance domain | Crypto primitive (Rust `crates/crypto`; TS `packages/crypto`) | Core codec (`packages/core/src/node/seal.ts` — the only caller of `buildNodeAad` with a `node.id`) | `uuidToBytes`/`Uuid::parse_str` are foundational parsers consumed by the AAD builder; tightening happens once at the primitive, not at each call site |
| Cross-language vector generation/fixtures | Test infrastructure (`scripts/gen-*.ts`, `tests/vectors/`) | Both Rust and TS test suites | Vectors are the single artifact both languages assert against — this phase's whole premise is that these files are the parity contract |

## Standard Stack

No new libraries. This phase edits existing first-party code only:

| Component | Location | Role in this phase |
|-----------|----------|--------------------|
| `ciborium` (Rust CBOR) | `crates/core/src/ipns.rs` | Already used to decode `Validity`/`ValidityType` CBOR map entries |
| `cborg` (TS CBOR, via `ipns` npm dep) | `scripts/gen-ipns-verify-vectors.ts`, sdk-core resolve path | Already used for CBOR encode/decode; no new usage needed |
| `uuid` crate v1.20.0 (Rust) | `crates/crypto/src/aes.rs` | `Uuid::parse_str` — the UUID acceptance domain being tightened |
| Hand-rolled `uuidToBytes` (TS) | `packages/crypto/src/utils/encoding.ts` | The looser acceptance domain being tightened to match Rust (or vice versa, per the chosen policy) |

**Version verification:** `uuid = "1"` pinned in root `Cargo.toml` (workspace dep), resolved to **1.20.0** in `Cargo.lock` `[VERIFIED: Cargo.lock]`. No package installs required for this phase — do not run `npm install`/`cargo add`; Package Legitimacy Audit is N/A.

## Package Legitimacy Audit

Not applicable — this phase installs no new external packages. All work is edits to existing first-party crates/packages and shared JSON test vectors.

## Architecture Patterns

### System Architecture Diagram

```
                    ┌─────────────────────────────────────────┐
                    │   tests/vectors/  (shared JSON fixtures) │
                    │  ipns/verify.json · node-codec.json      │
                    │  crypto/node-aad.json                    │
                    └───────────────┬───────────────────────────┘
                                    │  loaded by BOTH sides
              ┌─────────────────────┼─────────────────────┐
              ▼                                            ▼
   ┌─────────────────────────┐              ┌─────────────────────────────┐
   │  Rust (source of truth) │              │  TypeScript (must match)    │
   │                         │              │                              │
   │ crates/core/ipns.rs     │              │ packages/sdk-core/src/ipns  │
   │  decode_ipns_cbor_      │              │  /index.ts resolveIpnsRecord│
   │  validity() [+ValType]  │◄── parity ──►│  (Validity parse + skew)    │
   │                         │              │                              │
   │ crates/api-client/      │              │ (TS has no separate         │
   │  ipns.rs bind_verified()│              │  bind_verified — inlined    │
   │  parse_rfc3339_to_      │              │  in resolveIpnsRecord)      │
   │  unix_secs()            │              │                              │
   │                         │              │                              │
   │ crates/fuse/tests/      │              │ packages/sdk-core/src/      │
   │  ipns_verify_vectors.rs │              │  __tests__/ipns.test.ts     │
   │  classify_vector()      │              │  (D-11/D-12 vector suite)   │
   │  [missing EOL leg]      │              │                              │
   │                         │              │                              │
   │ crates/core/src/node/*  │              │ packages/core/src/node/*    │
   │  (fileIv: String,       │◄── parity ──►│  (fileIv: string,           │
   │  passthrough, no decode)│              │  passthrough, no decode)    │
   │                         │              │                              │
   │ crates/crypto/aes.rs    │              │ packages/crypto/src/utils/  │
   │  Uuid::parse_str()      │◄── parity ──►│  encoding.ts uuidToBytes()  │
   └─────────────────────────┘              └─────────────────────────────┘
              │                                            │
              ▼                                            ▼
   crates/fuse/content_ops.rs,              apps/web/src/services/download.
   journal_helpers.rs — actual              service.ts, useFileVersions.ts,
   base64ToBytes(file_iv) decode            useStreamingPreview.ts — actual
   for AES-GCM/CTR decrypt                  base64ToBytes(fileIv) decode
   (ALREADY base64, fixed post-P69)         (ALREADY base64, canonical)
```

### Recommended Project Structure

No new files/directories. Changes land in-place across:

```
crates/core/src/ipns.rs                         # decode_ipns_cbor_validity: add ValidityType read
crates/api-client/src/ipns.rs                    # bind_verified: gate on ValidityType==0; parse_rfc3339_to_unix_secs unchanged (already strict)
crates/fuse/tests/ipns_verify_vectors.rs         # classify_vector: add EOL/expiry/ValidityType leg
packages/sdk-core/src/ipns/index.ts              # resolveIpnsRecord: strict RFC3339 parse + ValidityType==0 gate
scripts/gen-ipns-verify-vectors.ts               # extend to emit expired + wrong-validity-type + malformed-rfc3339 cases
tests/vectors/ipns/verify.json                   # regenerated, new case count (>8)
tests/vectors/node-codec.json                    # file_iv/versions[].fileIv sample values made encoding-unambiguous
packages/core/src/__tests__/node-codec-vectors.test.ts   # NEW assertion: base64-decode fileIv, pin byte length/value
crates/core/tests/node_codec_vectors.rs          # NEW assertion: base64::decode fileIv, pin byte length/value
packages/crypto/src/utils/encoding.ts            # uuidToBytes: tighten to canonical-only (Option A)
crates/crypto/src/aes.rs                         # build_node_aad: tighten Uuid parsing to canonical-only (Option A)
tests/vectors/crypto/node-aad.json               # (optional) add divergent-form UUID cases if a new KAT is added
```

### Pattern 1: Shared JSON vector as the parity oracle

**What:** A single `tests/vectors/**/*.json` file is loaded by both a Rust `#[test]` and a TS `vitest` test; both assert their own implementation reaches the same `expected_result`/`expected_*_hex` as the fixture.
**When to use:** Any time a cross-language byte-identical or verdict-identical guarantee is claimed. This is the existing, established pattern in this repo (`ipns_verify_vectors.rs` / `ipns.test.ts`, `node_codec_vectors.rs` / `node-codec-vectors.test.ts`, `cross_language.rs` / crypto vitest).
**Example (current, from `crates/fuse/tests/ipns_verify_vectors.rs`):**
```rust
// Source: crates/fuse/tests/ipns_verify_vectors.rs:161-175 (current)
#[test]
fn ipns_verify_cross_language() {
    let vectors: Vec<IpnsVerifyVector> = load_vectors("ipns/verify.json");
    assert!(!vectors.is_empty(), "No IPNS verify vectors loaded");
    assert_eq!(vectors.len(), 8, "Expected exactly 8 IPNS verify vectors");
    for v in &vectors {
        let actual = classify_vector(v);
        assert_eq!(actual, v.expected_result, "IPNS verify vector mismatch for: {}", v.description);
    }
}
```
This phase must (a) extend the vector count (the `assert_eq!(vectors.len(), 8, ...)` hard-coded count is a **must-update** guard on both the Rust test and the TS counterpart's `expect(vectors.length).toBe(8)` assertion at `packages/sdk-core/src/__tests__/ipns.test.ts:527`), and (b) extend `classify_vector` to also perform the EOL/ValidityType check so `"expired"`/`"wrong-validity-type"` vectors are actually exercised, not just added to the fixture and silently ignored by the classifier's binding logic (today's gap #9).

### Pattern 2: `pub(crate)` visibility blocks cross-crate test reuse

**What:** `bind_verified` in `crates/api-client/src/ipns.rs:66` is declared `pub(crate) fn bind_verified(...)`. The todo's preferred fix ("exporting a single binding helper from `cipherbox-api-client` and reusing it [in `crates/fuse/tests/ipns_verify_vectors.rs`]") requires widening this to `pub` — it currently cannot be called from `crates/fuse`'s test crate at all.
**When to use:** This phase must decide: widen `bind_verified` to `pub` and delete `classify_vector`'s hand-duplicated binding logic in favor of calling it directly, OR keep `classify_vector` as a parallel hand-spelled implementation and extend it in lockstep (current pattern, per its own doc comment: "equivalent to `bind_verified(&resp, verdict)` but spelled out explicitly"). **Recommendation: widen `bind_verified` to `pub`.** The whole point of Phase 75 is eliminating drift between a real implementation and a test-only reimplementation — the existing `classify_vector` duplication is itself a drift vector (it is how gap #9 arose: the duplicate fell behind when D-07 added the EOL check to `bind_verified` but nobody updated the duplicate). `VerifyError` and `VerifiedResolve` are already `pub`; only the function itself needs the visibility change.
**Example:**
```rust
// crates/api-client/src/ipns.rs:66 (current — must become `pub`)
pub(crate) fn bind_verified(
    resp: &IpnsResolveResponse,
    sig_verdict: Option<bool>,
) -> Result<VerifiedResolve, VerifyError> {
```

### Pattern 3: KAT must decode, not just carry, encoding-sensitive fields

**What:** `tests/vectors/node-codec.json`'s `fileIv`/`versions[].fileIv` are `String` (Rust) / `string` (TS) fields on `NodeContent`/`VersionEntry`. The codec (`packages/core/src/node/{encode,decode}.ts`, `crates/core/src/node/types.rs`) treats them as **opaque pass-through strings** — never decoded to bytes, never re-encoded. This is confirmed by reading `packages/core/src/node/encode.ts:57,66` (`fileIv: content.fileIv` — direct copy) and `crates/core/src/node/types.rs:66,82` (`pub file_iv: String`).
**Why it matters (root cause of the "just change the sample" trap):** The existing KAT (`node_codec_round_trips_and_byte_matches_kat` in `crates/core/tests/node_codec_vectors.rs:42-84`, and the four `it()` blocks in `packages/core/src/__tests__/node-codec-vectors.test.ts:106-130`) only asserts `toHex(encodeReadBody(node)) === expected_read_body_hex` — a **string-in, string-out JSON round-trip**. Changing `file_iv`'s sample value to something "valid in exactly one encoding" changes nothing about what the KAT can detect, because **neither KAT consumer ever attempts to decode `fileIv` as bytes at all.** A hex-vs-base64 implementation divergence would still round-trip through this test undetected regardless of sample value, because the test never calls a decoder on that field.
**Recommendation:** The fix is NOT (only) "pick an unambiguous sample" — it is "add a NEW assertion" that actually exercises the encoding-sensitive decode path both languages use in production (`base64ToBytes(fileIv)` in TS at `apps/web/src/services/download.service.ts:128` / `packages/sdk-core/src/file/index.ts:414`; `base64::engine::general_purpose::STANDARD.decode(&content.file_iv)` in Rust at `crates/fuse/src/journal_helpers.rs:151-156`). Concretely: add a helper in each KAT test file that does `base64ToBytes(vector.node.content.fileIv)` / `base64::decode(...)` and asserts the decoded length matches a new fixture field, e.g. `expected_file_iv_len_bytes: 12`. Then pick a sample that is valid base64 but invalid (or wrong-length) as hex, so a regression that swaps the decoder produces either a decode error or a length mismatch that fails the new assertion.
**Byte-length constraint on the new sample:** production GCM IVs are 12 bytes, CTR IVs are 16 bytes (confirmed via `crates/fuse/src/content_ops.rs:157-168`: `[u8; 16]` for CTR, `[u8; 12]` for GCM after base64 decode). A base64 string encoding exactly 16 bytes will naturally end in `==` padding (16 mod 3 = 1 → 2 padding chars), which is automatically hex-invalid — trivial to satisfy for the CTR samples. A base64 string encoding exactly 12 bytes (12 is a multiple of 3, so **no padding**, 16 chars) needs a byte pattern deliberately chosen so at least one output character falls outside `[0-9a-f]` (e.g. a byte whose top-4-bit base64 group maps to an uppercase letter, `+`, or `/`) — verify this programmatically (`Buffer.from(bytes).toString('base64')` and assert `/[^0-9a-f]/i.test(str)` is false is what you're avoiding — you want it to be true, i.e. contain a non-hex char) rather than hand-deriving it, since base64's 6-bit grouping does not align with hex's 4-bit nibbles.
**Scope note on `node-aad.json`'s `iv` field:** `tests/vectors/crypto/node-aad.json`'s `seal_vectors[0].iv` and `node-codec.json`'s `seal_vectors[0].fixed_iv` (both `"000102030405060708090a0b"`) are a **different field, not affected by this bug class**. Both KAT consumers decode these explicitly via `fromHex()`/`hex::decode()` only (confirmed: `packages/core/src/__tests__/node-codec-vectors.test.ts:145` `const fixedIv = fromHex(sv.fixed_iv);`; `packages/crypto/src/__tests__/build-node-aad.test.ts:357-358` `const iv = hexToBytes(v.iv);`) — there is no base64 code path for these test-harness IV parameters, so no encoding ambiguity exists here regardless of the shared value. Do not touch these; the todo's "and any `node-aad.json` seal vector carrying an IV" instruction is precautionary but this repo's current code shows it is not actually at risk — confirm this in the plan rather than blindly editing both files.

### Pattern 4: Canonical UUID producers never emit non-canonical forms — tightening is safe

**What:** Every `node.id`/`childId` fed into `buildNodeAad`/`build_node_aad` in production originates from `crypto.randomUUID()` (TS: `packages/sdk-core/src/file/index.ts:262`, `packages/sdk-core/src/folder/registration.ts:67`, `packages/sdk-core/src/vault/index.ts:152`, `packages/sdk/src/client.ts:2447,3141,3396`, `packages/sdk/src/share/shared-write.ts:333,456`) or `generate_uuid_v4()` (Rust: `crates/crypto/src/utils.rs:45-54`, called from `crates/fuse/src/write_ops/implementation/delete.rs`, `crates/fuse/src/platform/windows/write_ops.rs`, `crates/sdk/src/emit.rs`). Both always produce lowercase, hyphenated, canonical 8-4-4-12 output — `crypto.randomUUID()` per the Web Crypto spec `[ASSUMED: spec knowledge, not verified via docs.rs/MDN this session]`, and `generate_uuid_v4()` by explicit `format!("{:02x}...-{:02x}...")` construction `[VERIFIED: crates/crypto/src/utils.rs:47-54 read directly]`.
**Grep confirmation (per the todo's CRITICAL instruction):** `grep -rn "buildNodeAad(" packages/ apps/` (excluding tests) returns only call sites inside `packages/core/src/node/seal.ts` passing `node.id`/`childId`/`nodeId`, all of which trace back to `crypto.randomUUID()` at creation time. No call site passes a simple-32-hex, uppercase, braced, or urn-prefixed string. `packages/crypto/src/__tests__/build-node-aad.test.ts` (all 508 lines read) uses only two UUID constants, both canonical lowercase-hyphenated (`550e8400-e29b-41d4-a716-446655440000`, `12345678-1234-1234-1234-1234567890ab`) — **no test exercises simple-32-hex, uppercase, braced, or urn forms today.** `[VERIFIED: direct grep + full-file read this session]`
**Conclusion:** Tightening TS `uuidToBytes` to reject simple-32-hex (Option A) will not break any existing caller or test in this repo.

### Anti-Patterns to Avoid

- **Fixing ValidityType enforcement on only one side:** the first todo (`2026-06-24-ts-resolve-strict-rfc3339-validity-parity`) explicitly documents that CodeRabbit's original suggestion to add ValidityType enforcement to Rust-only was **rejected as a false positive / parity-breaker** — both sides currently ignore `ValidityType` identically, so it must be added to both simultaneously (this phase's second todo) or not at all.
- **Regenerating `tests/vectors/ipns/verify.json` by hand-editing bytes:** the file's `data`/`signature_v2` fields are real Ed25519-signed CBOR bytes produced by `scripts/gen-ipns-verify-vectors.ts`. New cases (expired, wrong-validity-type, malformed-RFC3339) must be added by extending that generator script and re-running it (`npx tsx scripts/gen-ipns-verify-vectors.ts`, after `pnpm --filter @cipherbox/core build`), never hand-crafted — a malformed CBOR/signature byte pair would make the vector meaningless.
- **Treating "change the sample value" as sufficient for the node-codec KAT fix:** per Pattern 3 above, this is a structural trap — verify a NEW decode-assertion actually exists before considering SC#2 met.
- **Silently widening `bind_verified` without updating `crates/fuse/tests/ipns_verify_vectors.rs`'s `classify_vector`:** if the plan chooses to keep the duplicate (not recommended, see Pattern 2), any change to `bind_verified`'s logic (ValidityType gate) must be mirrored by hand in `classify_vector` or gap #9's root cause (silent drift) recurs immediately.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| RFC3339 parsing in Rust | A new/second parser | The existing hardened `parse_rfc3339_to_unix_secs` in `crates/api-client/src/ipns.rs:190-261` | Already handles leap years, impossible-date rejection (Hinnant civil_from_days), trailing-component rejection — it is the parser TS must mirror, not duplicate independently |
| RFC3339 parsing in TS | A date library dependency (e.g. `date-fns`, `luxon`) or a second hand-rolled parser divergent from Rust's rules | A hand-written strict parser mirroring the exact Rust rules (see Code Examples) — `new Date(...)` must be replaced, not augmented | `new Date()` accepts a wide superset of non-canonical formats (per MDN/ECMA-262 `Date.parse` `[ASSUMED]`); a library adds a dependency for logic that must byte-for-byte match ~70 lines of existing Rust, which is easier to hand-port line-by-line than to reconcile against a third implementation's edge cases |
| CBOR encode/decode | Any new library | `ciborium` (Rust, already a dep) / `cborg` (TS, already used in the generator script) | Already wired into both the codec and the vector generator |
| UUID parsing | A new validation library | Tighten the existing `uuidToBytes` regex (TS) / rely on `uuid::Uuid::parse_str`'s existing strictness plus an explicit canonical-form pre-check (Rust) | Both existing implementations are correct within their own acceptance domain; the fix is narrowing acceptance, not swapping parsers |

**Key insight:** every piece of this phase is "make an existing, already-correct-in-isolation implementation agree with its cross-language twin" — there is no new algorithm to write, only precise mirroring of already-audited logic (the Rust RFC3339 parser was itself hardened and reviewed in Phase 60; the UUID acceptance domains were audited in the Phase 61 security review).

## Common Pitfalls

### Pitfall 1: Treating the node-codec KAT sample-value change as self-sufficient

**What goes wrong:** A plan that only changes `file_iv: "000102030405060708090a0b"` to a new ambiguous-encoding string, without adding a decode-and-assert step, will pass CI trivially (the string round-trips through JSON either way) while leaving SC#2 ("a hex-encoded `file_iv` fails the node-codec KAT") structurally unmet — a hex-encoded regression would still round-trip through the unchanged opaque-string test.
**Why it happens:** The todo's phrasing ("Change the `file_iv` sample ... to a value that is valid in exactly one encoding") reads as if the sample alone is the fix; the codec's opaque-string treatment is a non-obvious prerequisite gap only visible by reading `encode.ts`/`decode.ts`/`types.rs` directly (done this session).
**How to avoid:** The plan MUST include a task that adds an explicit `base64ToBytes(fileIv)` / `base64::decode(&file_iv)` assertion (with an expected-length or expected-bytes-hex fixture field) to both `packages/core/src/__tests__/node-codec-vectors.test.ts` and `crates/core/tests/node_codec_vectors.rs`.
**Warning signs:** If the plan's verification step for SC#2 is "assert the JSON round-trips with the new sample," it has not actually locked the encoding.

### Pitfall 2: `assert_eq!(vectors.len(), 8, ...)` / `expect(vectors.length).toBe(8)` hard-coded counts

**What goes wrong:** Adding new cases to `tests/vectors/ipns/verify.json` (expired, wrong-validity-type) without updating BOTH hard-coded length assertions (`crates/fuse/tests/ipns_verify_vectors.rs:165` and `packages/sdk-core/src/__tests__/ipns.test.ts:527`) causes an immediate, unrelated-looking test failure that's easy to "fix" by just bumping the number without checking the new cases are actually exercised end-to-end.
**Why it happens:** These are intentional anti-vacuous-pass guards (per their own comments, e.g. `node_codec_vectors.rs:44-48` "Non-vacuous vector-count guard") — they are doing their job correctly, but a plan that doesn't anticipate them will treat the failure as a blocker rather than an expected checkpoint.
**How to avoid:** Explicitly plan the new vector count and update both guards in the same task as the generator-script extension.
**Warning signs:** CI red on an assertion that says "Expected exactly N vectors" after adding vectors — this is expected, not a regression.

### Pitfall 3: `decode_ipns_cbor_validity`'s signature change ripples to 3 call sites

**What goes wrong:** Adding `ValidityType` extraction requires changing `decode_ipns_cbor_validity`'s return type (currently `Result<Option<Vec<u8>>, IpnsError>` for `Validity` bytes only). This function is called from `crates/api-client/src/ipns.rs:121` (`bind_verified`) and has its own unit tests in `crates/core/src/ipns.rs` (`decode_ipns_cbor_validity_rejects_duplicate_validity_key` at line 584, and others near line 629). A signature change that isn't threaded through all call sites will fail to compile, not fail silently — but a plan that doesn't anticipate the blast radius will underestimate the task.
**How to avoid:** Plan a single task scoped to "extend `decode_ipns_cbor_validity` to also return `ValidityType`, update its ~2-3 existing unit tests, update `bind_verified`'s one call site to gate on the new value."
**Warning signs:** N/A — this fails at `cargo check`, so it self-detects; listed here for task-sizing accuracy.

### Pitfall 4: `bind_verified` visibility (`pub(crate)`) blocks the todo's preferred dedup

**What goes wrong:** A plan that says "export a single binding helper from `cipherbox-api-client` and reuse it in the vector classifier" without an explicit task to change `pub(crate) fn bind_verified` to `pub fn bind_verified` will discover the compile error mid-execution rather than during planning.
**How to avoid:** Include the visibility change as an explicit sub-task; see Pattern 2 above for the recommended direction (widen and delete the duplicate `classify_vector` binding logic, don't just widen and leave two implementations).

## Runtime State Inventory

Not applicable — this is not a rename/refactor/migration phase. No stored data, service config, OS-registered state, secrets, or build artifacts carry the renamed/changed identifiers; this phase edits parsing/validation logic and test vectors only, with no schema or naming changes.

## Code Examples

### Current Rust strict RFC3339 parser (the parity target for TS)

```rust
// Source: crates/api-client/src/ipns.rs:190-261 (current, verified this session)
fn parse_rfc3339_to_unix_secs(s: &str) -> Option<u64> {
    // Expected format: "2026-01-01T00:00:00.000000000Z" (29 chars minimum, ends with Z).
    // Tolerate missing nanoseconds: "2026-01-01T00:00:00Z" also valid.
    let s = s.strip_suffix('Z')?;
    let (date_part, time_part) = s.split_once('T')?;

    let mut date_parts = date_part.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    // Reject trailing date components (e.g. "2026-01-01-99").
    if date_parts.next().is_some() { return None; }

    let mut dot = time_part.splitn(2, '.');
    let time_no_nanos = dot.next()?;
    if let Some(frac) = dot.next() {
        if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) { return None; }
    }
    let mut time_parts = time_no_nanos.split(':');
    let hour: u64 = time_parts.next()?.parse().ok()?;
    let minute: u64 = time_parts.next()?.parse().ok()?;
    let second: u64 = time_parts.next()?.parse().ok()?;
    // Reject trailing time components (e.g. "00:00:00:99").
    if time_parts.next().is_some() { return None; }

    // Range + leap-aware day-of-month validation (rejects e.g. 2026-02-31 rather than
    // silently rolling it into March — fail-closed, not "extend validity").
    if month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59 { return None; }
    let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => if is_leap { 29 } else { 28 },
        _ => return None,
    };
    if day > days_in_month { return None; }
    // ... Hinnant civil_from_days conversion to unix seconds (see full source) ...
}
```

**TS port must replicate exactly:** strip trailing `Z` (reject if absent — note both sides already require the `Z` suffix, no timezone-offset support), split on `T`, reject >3 dash-separated date components, reject a non-empty-but-non-digit fractional-seconds part, reject >3 colon-separated time components, validate month/day/hour/minute/second ranges INCLUDING leap-year-aware day-of-month (do not let `new Date()` or a naive Date construction silently roll an impossible date forward).

### Current TS loose parser (must be replaced)

```typescript
// Source: packages/sdk-core/src/ipns/index.ts:307-319 (current, verified this session)
const validityBytes = cborFields['Validity'];
if (!(validityBytes instanceof Uint8Array)) {
  throw new Error('IPNS record has no Validity field — fail closed');
}
const validityStr = new TextDecoder().decode(validityBytes);
const expiryMs = new Date(validityStr).getTime();   // <-- TOO LOOSE, replace this line
if (isNaN(expiryMs)) {
  throw new Error(`IPNS record has unparseable Validity field: ${validityStr}`);
}
const skewBufferMs = 5 * 60 * 1000; // 5 minutes
if (expiryMs < Date.now() - skewBufferMs) {
  throw new Error(`IPNS record expired: validity=${validityStr}`);
}
```
The skew-buffer logic (5 min, `Date.now()` comparison) stays; only the `new Date(validityStr).getTime()` line and its surrounding parse are replaced by a strict hand-ported parser returning `number | null` (unix ms or seconds — pick one unit and convert consistently with the Rust side, which works in whole seconds).

### Current CBOR field layout (both languages must agree on key presence)

```rust
// Source: crates/core/src/ipns.rs:166-195 (build_cbor_data — canonical field order)
// TTL, Value, Sequence, Validity, ValidityType — ValidityType is CborValue::Integer(0.into())
```
```typescript
// Source: scripts/gen-ipns-verify-vectors.ts:126-134 (buildCborData — TS mirror, already includes ValidityType: 0)
return cborEncode({
  TTL: 300000000000,
  Value: new TextEncoder().encode(`/ipfs/${cid}`),
  Sequence: sequenceNumber,
  Validity: new TextEncoder().encode('2099-01-01T00:00:00.000000000Z'),
  ValidityType: 0,
});
```
Both sides already encode `ValidityType: 0` on every produced record — the gap is purely on the **decode/verify** side never reading it back.

### Current `uuidToBytes` (TS, too loose — tighten per Option A)

```typescript
// Source: packages/crypto/src/utils/encoding.ts:58-64 (current)
export function uuidToBytes(uuid: string): Uint8Array {
  const clean = uuid.replace(/-/g, '');          // strips ALL hyphens regardless of position
  if (!/^[0-9a-fA-F]{32}$/.test(clean)) {
    throw new CryptoError('Malformed UUID', 'INVALID_AAD_INPUT');
  }
  return hexToBytes(clean);
}
```
**Option A tightened form** (recommended): replace the strip-then-check with a single canonical-form regex, e.g. `/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/`, then strip hyphens only after that match succeeds (so loose-hyphen and no-hyphen forms are rejected, matching Rust's rejection of arbitrary hyphen placement while also now rejecting simple-32-hex, which the todo flags as the one form TS currently accepts that Rust doesn't).

### Current Rust `build_node_aad` UUID parse (too loose in the other direction — accepts braced/urn)

```rust
// Source: crates/crypto/src/aes.rs:172 (current)
let uuid = Uuid::parse_str(node_id).map_err(|_| CryptoError::InvalidAadInput)?;
```
`Uuid::parse_str` (uuid crate 1.20.0) accepts hyphenated, simple (no-hyphen), braced (`{...}`), and urn (`urn:uuid:...`) forms `[ASSUMED: uuid crate documented behavior, not fetched from docs.rs this session — but consistent with the todo's own Phase-61-review-sourced acceptance table and with the absence of any Rust test in `crates/crypto/src/aes.rs` exercising braced/urn forms to contradict it]`. **Option A tightened form:** add an explicit canonical-form string check (same regex shape as the TS side) before calling `Uuid::parse_str`, so braced/urn/simple forms are rejected even though the underlying crate would accept them.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| `new Date(validityStr).getTime()` for IPNS expiry | Hand-written strict RFC3339 parser (Rust side already done, Phase 60) | Rust hardened in Phase 60 (`60-01`); TS still on old approach — this phase's job | TS currently accepts malformed timestamps Rust rejects (documented, non-exploitable per the todo since Ed25519 covers the whole CBOR) |
| `ValidityType` unread on both sides | (target state) `ValidityType == 0` required before treating `Validity` as EOL, both sides | Not yet — this phase | Currently in parity (both ignore it) but not defense-in-depth; a conformant signer only ever emits `ValidityType: 0` today |
| node-codec KAT as opaque-string round-trip | (target state) KAT also decodes `fileIv` as bytes and pins length/value | The Phase 69 desktop-e2e incident exposed the gap in production (already fixed there); this phase closes the KAT-side blind spot | Currently a regression could reintroduce the P69 bug and no committed test would catch it |
| TS/Rust UUID acceptance domains diverge (documented LOW-1 from Phase 61) | (target state) identical acceptance domain, either Option A or B | Phase 61 security review flagged it (SHIP verdict, not blocking); LOW-2 already fixed (`f1a81344f`) | Not exploitable today (fail-closed on both sides for divergent inputs) but violates the phase's own "byte mismatch is silent total decryption failure" premise if a non-canonical `node_id` ever appears |

**Deprecated/outdated:** `new Date(...)`-based Validity parsing in `packages/sdk-core/src/ipns/index.ts` is the one piece of code in this phase's scope that is unambiguously being removed, not extended.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|----------------|
| A1 | `crypto.randomUUID()` (Web Crypto / Node.js built-in) always produces lowercase-hyphenated canonical UUIDs, never uppercase/braced/urn forms | Pattern 4 | If wrong, Option A (canonical-only tightening) could reject a legitimately-produced `node_id` at runtime — low risk since this is a well-documented platform API behavior, but not verified via a fetched spec this session |
| A2 | `Uuid::parse_str` (uuid crate 1.20.0) accepts hyphenated / simple / braced / urn forms and rejects arbitrary-hyphen-placement, matching the todo's acceptance table | Code Examples, Pattern 4 | If the crate's actual behavior differs, the "Option A" tightening code (adding a canonical-regex pre-check) is still safe regardless — it narrows acceptance further than whatever the crate natively allows, so this assumption only affects the accuracy of the "why Rust is looser in this direction" narrative, not the correctness of the recommended fix |
| A3 | `new Date().getTime()` / `Date.parse()` (V8/ECMA-262) accepts a wide superset of non-canonical timestamp formats compared to strict RFC3339 | Don't Hand-Roll | Low risk — this is the well-known, widely-documented reason the todo exists in the first place (CodeRabbit finding), and the fix (replace, don't augment) is correct regardless of the exact superset boundary |

**Confirmation:** A1–A3 are LOW-risk framework/platform-behavior assumptions, not project-specific decisions — they do not require user confirmation before planning proceeds, but are logged per protocol. All four TODO-sourced technical claims (current code behavior, current test structure, current CI wiring) are `[VERIFIED]` via direct file reads this session, not `[ASSUMED]`.

## Open Questions (RESOLVED)

1. **Should `bind_verified` be widened to `pub` and `classify_vector`'s duplicate binding logic deleted, or should the duplicate be kept and manually extended?**
   - What we know: the todo prefers the dedup ("ideally by exporting a single binding helper ... and reusing it, rather than duplicating"); `bind_verified` is currently `pub(crate)`, blocking this from another crate's test target.
   - What's unclear: whether `crates/fuse`'s test target can depend on `cipherbox-api-client`'s test-only surface cleanly, or whether widening a production function's visibility for test reuse is acceptable per this repo's conventions (the doc comment on `classify_vector` suggests the duplication was a deliberate choice at the time, for reasons not stated).
   - Recommendation: widen to `pub` and delete the duplicate (Pattern 2) — the planner should confirm this is acceptable in the discuss/plan step, but it is the technically superior option since duplication is how gap #9 was created.
   - RESOLVED: Plan 75-02 adopts the recommendation — `bind_verified` is widened to `pub` and `classify_vector` delegates to it with the duplicate binding deleted (75-02-02 / 75-02-03).

2. **Exact new vector count for `tests/vectors/ipns/verify.json` after adding expired/wrong-validity-type/malformed-RFC3339 cases.**
   - What we know: currently exactly 8 cases, hard-guarded by count assertions in two places (Pitfall 2).
   - What's unclear: how many NEW cases the plan wants — the todos ask for at minimum "expired" and "wrong-validity-type" (todo 2) plus "malformed-timestamp cases" (todo 1) — could be as few as 2 new cases or as many as 5+ if multiple malformed-RFC3339 sub-cases (trailing component, impossible date, non-digit fraction) are each given their own vector.
   - Recommendation: the planner should enumerate the exact case list per the two todos' wording before sizing tasks; suggest at minimum: `expired-valid-sig`, `wrong-validity-type` (ValidityType=1 or absent), `malformed-rfc3339-trailing-component`, `malformed-rfc3339-impossible-date` — 4 new cases, bringing the total to 12.
   - RESOLVED: Plan 75-01 adopts the recommendation — the generator adds the 4 new invalid cases (expired, wrong-validity-type, and two malformed-RFC3339 sub-cases) for a total of 12 cases, and the hard-coded count assertions are updated to 12.

## Environment Availability

Skipped — no external dependency changes. This phase edits existing Rust/TS code and JSON fixtures within an already-configured monorepo; no new tools, services, or runtimes are introduced.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Rust framework | Cargo's built-in `#[test]` harness (workspace-wide via `cargo test --workspace`) |
| TS framework | Vitest (`vitest run`), per-package (`@cipherbox/crypto`, `@cipherbox/core`, `@cipherbox/sdk-core`) |
| Config files | `Cargo.toml` (workspace root); `packages/*/vitest.config.ts` (existing, no changes needed) |
| Quick run (RFC3339/ValidityType) | `cargo test -p cipherbox-api-client ipns::` and `pnpm --filter @cipherbox/sdk-core test -- ipns` |
| Quick run (node-codec KAT) | `cargo test -p cipherbox-core --test node_codec_vectors` and `pnpm --filter @cipherbox/core test -- node-codec-vectors` |
| Quick run (UUID/AAD) | `cargo test -p cipherbox-crypto build_node_aad` and `pnpm --filter @cipherbox/crypto test -- build-node-aad` |
| Quick run (IPNS verify vectors, cross-lang) | `cargo test -p cipherbox-fuse --test ipns_verify_vectors` |
| Full suite (Rust) | `cargo test --workspace` |
| Full suite (Rust, exact CI-matching invocation) | `cargo llvm-cov --workspace --no-default-features --features fuse --lcov --output-path desktop-lcov.info` (Linux job) |
| Full suite (TS) | `pnpm --filter @cipherbox/crypto test && pnpm --filter @cipherbox/core test && pnpm --filter @cipherbox/sdk-core test` |
| Cross-language vector parity CI job | `.github/workflows/ci.yml` job `vector-parity` (display name "Cross-Language Vector Parity") — **NOTE: this job currently only runs `cargo test -p cipherbox-crypto --test cross_language` + `@cipherbox/crypto` vitest + `scripts/check-vector-parity.sh`. It does NOT run `ipns_verify_vectors.rs` or `node_codec_vectors.rs` — those are exercised by the separate `cargo-linux` job's `cargo llvm-cov --workspace` step. Both jobs matter for this phase; do not assume `vector-parity` alone covers SC#1/#2.** |
| SDK E2E gate | `.github/workflows/ci.yml` job `sdk-e2e` (display name "SDK E2E Tests"), runs `pnpm --filter @cipherbox/sdk-e2e test` against a real local API — real client→API IPNS round-trip, per project memory the only such gate |

### Phase Requirements → Test Map

This phase has no `REQUIREMENTS.md` requirement IDs (it is an M4 closeout phase sourced directly from todos, not from the v2.0 CRYPTO/NODE/... requirement set). Mapping is by Success Criterion instead:

| SC | Behavior | Test Type | Automated Command | File Exists? |
|----|----------|-----------|---------------------|--------------|
| SC1 | Malformed/out-of-range RFC3339 Validity rejected identically Rust+TS | unit + cross-lang vector | `cargo test -p cipherbox-api-client && pnpm --filter @cipherbox/sdk-core test -- ipns` | ✅ files exist, ❌ new malformed-RFC3339 vector cases — Wave 0 |
| SC1 | `ValidityType!=0` record rejected identically Rust+TS | unit + cross-lang vector | `cargo test -p cipherbox-fuse --test ipns_verify_vectors && pnpm --filter @cipherbox/sdk-core test -- ipns` | ❌ `classify_vector`'s EOL/ValidityType leg — Wave 0 |
| SC2 | Hex-encoded `file_iv` fails the node-codec KAT | unit (new decode assertion) | `cargo test -p cipherbox-core --test node_codec_vectors && pnpm --filter @cipherbox/core test -- node-codec-vectors` | ❌ new base64-decode assertion in both files — Wave 0 |
| SC3 | TS/Rust identical UUID acceptance domain, locked by cross-language KAT | unit + (new) cross-lang vector | `cargo test -p cipherbox-crypto build_node_aad && pnpm --filter @cipherbox/crypto test -- build-node-aad` | ❌ new divergent-form vectors in `node-aad.json` (or a new dedicated UUID-acceptance vector file) — Wave 0 |

### Sampling Rate

- **Per task commit:** the relevant quick-run command from the table above for the file(s) touched.
- **Per wave merge:** `cargo test --workspace` + full TS test suite across `@cipherbox/crypto`, `@cipherbox/core`, `@cipherbox/sdk-core`.
- **Phase gate:** both CI jobs (`vector-parity` and `cargo-linux`'s full workspace test) green, plus `sdk-e2e` unaffected (this phase should not touch the API/relay layer — TEE/API code is out of scope; confirm no regression via `pnpm --filter @cipherbox/sdk-e2e test` if IPNS resolve-path changes are broad).

### Wave 0 Gaps

- [ ] `scripts/gen-ipns-verify-vectors.ts` — extend generator to emit expired / wrong-validity-type / malformed-RFC3339 cases (needed before any new vector-based test can pass)
- [ ] New assertion block in `packages/core/src/__tests__/node-codec-vectors.test.ts` — base64-decode `fileIv`/`versions[].fileIv`, pin decoded length/bytes
- [ ] New assertion block in `crates/core/tests/node_codec_vectors.rs` — mirror the above in Rust
- [ ] New or extended vector fixture for UUID acceptance-domain parity (either add divergent-form cases to `tests/vectors/crypto/node-aad.json`'s `aad_vectors`/a new array, or a new `tests/vectors/crypto/uuid-acceptance.json`) — no existing fixture pins the accept/reject boundary today
- [ ] `crates/api-client/src/ipns.rs::bind_verified` visibility change to `pub` (if Pattern 2's recommendation is adopted) — not a test file but blocks the test-reuse Wave 0 item below
- [ ] `crates/fuse/tests/ipns_verify_vectors.rs::classify_vector` — extend (or replace via the above) to add the EOL/expiry/ValidityType leg

*(Framework install: none needed — Cargo and Vitest are already fully configured across every touched crate/package.)*

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|----------------|---------|--------------------|
| V2 Authentication | No | Out of scope — this phase does not touch Web3Auth/session tokens |
| V3 Session Management | No | Out of scope |
| V4 Access Control | No | Out of scope — no authorization logic touched |
| V5 Input Validation | Yes | Strict RFC3339 parsing (reject malformed timestamps, fail-closed); strict UUID canonical-form validation (reject non-canonical forms, fail-closed) — both are input-validation hardening at a cryptographic trust boundary |
| V6 Cryptography | Yes | AAD construction (`buildNodeAad`/`build_node_aad`) is the exact input to AES-256-GCM AAD binding (CRYPTO-01/02 from Phase 61) — never hand-roll parsing here; IPNS Ed25519 signature verification's downstream binding (CBOR Validity/ValidityType extraction) is part of the existing `ipns` npm-package-compatible verification chain, not reimplemented crypto |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|-----------------------|
| Cross-language parser differential (Rust accepts X, TS accepts Y ⊃ X or vice versa) at a signature-verified trust boundary | Tampering / Repudiation | Shared JSON vectors as the parity oracle (this phase's whole approach); fail-closed on any ambiguous/malformed input on BOTH sides, never "accept if either side would accept" |
| AAD acceptance-domain divergence enabling a crafted `node_id` string to encode differently on each side (theoretical AAD-transplant surface) | Tampering | Canonical-form-only UUID acceptance (Option A) closes the surface entirely rather than trying to keep two independently-evolving looser domains in sync |
| Test-vector generator producing malformed/tamperable cross-language fixtures if hand-edited | Tampering (of the test oracle itself) | Vectors with real cryptographic material (Ed25519 sigs, CBOR bytes) MUST be produced by the committed generator script, never hand-edited (Anti-Pattern above) |
| KAT that round-trips a field without ever decoding it, silently missing an encoding-format regression (this phase's SC2 root cause) | Tampering (production bug that ships despite green tests) | Add explicit decode-and-assert steps for every wire field whose *encoding* (not just presence) is a correctness invariant, not just its string identity |

## Sources

### Primary (HIGH confidence — direct code reads this session)

- `packages/sdk-core/src/ipns/index.ts` (lines 260-329) — current TS resolve-side Validity/EOL logic
- `crates/core/src/ipns.rs` (lines 1-260, 584-632) — `decode_ipns_cbor_validity`, `build_cbor_data`, existing unit tests
- `crates/api-client/src/ipns.rs` (lines 1-261, 612-813) — `bind_verified`, `parse_rfc3339_to_unix_secs`, existing unit tests
- `crates/fuse/tests/ipns_verify_vectors.rs` (full file, 176 lines) — `classify_vector`, cross-language test structure
- `scripts/gen-ipns-verify-vectors.ts` (full file, 419 lines) — vector generator, current 8-case structure
- `tests/vectors/ipns/verify.json` (full file) — confirmed no expired-with-valid-sig vector exists today
- `tests/vectors/node-codec.json`, `tests/vectors/crypto/node-aad.json` (full files) — confirmed `file_iv`/`fixed_iv`/`iv` sample values and structure
- `crates/core/tests/node_codec_vectors.rs`, `packages/core/src/__tests__/node-codec-vectors.test.ts` (full files) — confirmed opaque-string-only KAT treatment of `fileIv`
- `packages/crypto/src/utils/encoding.ts`, `crates/crypto/src/aes.rs` (relevant sections + full test blocks) — `uuidToBytes`, `build_node_aad`, `Uuid::parse_str` usage
- `packages/crypto/src/__tests__/build-node-aad.test.ts` (full file, 508 lines) — confirmed no non-canonical UUID form is tested today
- `packages/core/src/node/{encode,decode,types}.ts`, `crates/core/src/node/types.rs` — confirmed `fileIv`/`file_iv` is opaque `String`/`string`, never decoded in the codec layer
- `crates/fuse/src/content_ops.rs`, `crates/fuse/src/journal_helpers.rs` — confirmed production base64 decode of `file_iv` (GCM 12-byte, CTR 16-byte), already fixed post-Phase-69
- `apps/web/src/services/download.service.ts`, `apps/web/src/hooks/useFileVersions.ts`, `apps/web/src/hooks/useStreamingPreview.ts`, `packages/sdk-core/src/file/index.ts`, `packages/sdk-core/src/download/index.ts`, `packages/sdk/src/client.ts`, `packages/sdk/src/share/shared-write.ts` — grep-confirmed all production `fileIv` consumption sites and their base64/hex conventions
- `.github/workflows/ci.yml` (lines 368-374, 542-546, 684-802, 803-847) — confirmed `vector-parity` job scope, `cargo-linux` full-workspace test job, `sdk-e2e` job
- `scripts/check-vector-parity.sh` (full file) — confirmed it is a meta-check (file existence/JSON validity), not a re-run of tests
- `Cargo.lock` — confirmed `uuid = 1.20.0`
- `.planning/todos/pending/2026-06-24-ts-resolve-strict-rfc3339-validity-parity.md`, `2026-06-24-harden-validity-type-and-vector-expiry-lockstep.md`, `2026-07-07-node-codec-kat-pin-file-iv-encoding.md`, `2026-06-28-harden-uuid-acceptance-parity-aad-builder.md`, `2026-06-29-node-codec-base64-helper-dedup.md` (full files) — the authoritative scope documents
- `.planning/ROADMAP.md` (Phase 75 section, lines 921-944) — phase goal/success criteria/depends-on
- `.planning/REQUIREMENTS.md`, `.planning/STATE.md`, `./CLAUDE.md`, `.planning/config.json` — project context

### Secondary (MEDIUM confidence)

None used — all findings this session were grounded in direct repository reads rather than web search or external docs, since this is a self-contained internal-parity phase with no external library research needed.

### Tertiary (LOW confidence)

- `crypto.randomUUID()` canonical-form-only output behavior (A1) and `uuid` crate 1.20.0's exact `parse_str` acceptance table (A2) — both `[ASSUMED]`, based on well-established platform/crate knowledge, not fetched from MDN/docs.rs this session. Neither assumption gates a correctness-critical decision (see Assumptions Log).

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new dependencies; all existing library usage confirmed via direct reads
- Architecture: HIGH — every claimed current-code behavior (function signatures, call sites, test structure, CI wiring) verified via direct file reads and greps this session, not inferred
- Pitfalls: HIGH — each pitfall traces to a specific line-numbered piece of current code (hard-coded vector counts, `pub(crate)` visibility, opaque-string KAT structure) discovered by reading the actual test/implementation files, not speculated

**Research date:** 2026-07-11
**Valid until:** 30 days (stable internal-code parity work; re-verify line numbers if any of the four source files are touched by an intervening phase before Phase 75 executes — Phase 76 onward do not touch these files per their own ROADMAP scope, so low drift risk)
