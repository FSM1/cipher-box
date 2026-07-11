# Crypto/Privacy Review — Phase 75 (cross-language IPNS + node-codec verification parity)

Date: 2026-07-11
Scope: static analysis of `git diff main...HEAD` for the listed files only. No tests run.
Focus: Rust/TS validity/EOL/ValidityType parity, adversarial-input safety, false-reject vs false-accept, hex/base64 domain confusion.

All findings below are gated by a valid Ed25519 signature over the malformed CBOR (the resolve
path verifies the signature before any of this logic runs). So none is a plaintext/key exposure.
They are cross-language **verdict-divergence / parser-differential** issues, which is precisely the
invariant this phase exists to guarantee ("one signed record → identical verdict in every
language"). Severity is calibrated to that: split-brain / availability / soundness-of-parity, not
key compromise.

---

## MEDIUM — TS `resolveIpnsRecord` does not reject duplicate CBOR map keys; Rust does (parity break)

Location:

- TS: `packages/sdk-core/src/ipns/index.ts:377` — `cborDecode(dataBytes)` (no options)
- Rust: `crates/core/src/ipns.rs` — `decode_ipns_cbor_validity` explicitly rejects duplicate
  `Validity`/`ValidityType` keys (and `decode_ipns_cbor_data` rejects duplicate `Value`/`Sequence`)

Issue: the TS side decodes with `cborg` using default options. In cborg 4.5.8,
`rejectDuplicateMapKeys` defaults to `false` (`node_modules/.pnpm/cborg@4.5.8/.../lib/decode.js:96,114`),
so duplicate map keys are silently accepted with **last-wins** semantics
(`obj[key] = value`, line 129). Rust's hand-rolled decoder returns `CborEncodingFailed`
(→ `VerifyError::Invalid`) on any duplicate `Validity`/`ValidityType`/`Value`/`Sequence` key —
the phase's stated "parser-differential / first-wins-vs-last-wins hardening."

Failure scenario: a validly-signed record whose CBOR data map contains two `ValidityType`
entries, `1` then `0` (or two `Validity` entries: a past date then a future date).

- Rust `bind_verified` → duplicate ValidityType → `CborEncodingFailed` → **reject**.
- TS: cborg last-wins → `cborFields['ValidityType'] === 0` → passes the `!== 0` gate → **accept**
  (assuming signature + other bindings pass).

Result: web (TS) accepts a record desktop/FUSE (Rust) rejects — split-brain, and a downgrade
vector where the stricter client's rejection is bypassed on the web client. The four new
`verify.json` vectors do **not** include a duplicate-key case, so the oracle does not catch this.

Recommendation: pass the option so TS matches Rust exactly.

```ts
const cborFields = cborDecode(dataBytes, { rejectDuplicateMapKeys: true }) as Record<string, unknown>;
```

Add a `duplicate-validity-type` (and `duplicate-validity`) vector to `tests/vectors/ipns/verify.json`
so parity is pinned.

---

## MEDIUM — Rust RFC3339 parser accepts a leading `+` on numeric fields; TS rejects it (parity break, opposite direction)

Location:

- Rust: `crates/api-client/src/ipns.rs:217-219,235-237` — `date_parts.next()?.parse().ok()?`
  for `year: i64`, `month: u32`, `day: u32`, and `hour/minute/second: u64`
- TS: `packages/sdk-core/src/ipns/index.ts` — `isAllDigits()` (`/^[0-9]+$/`) gate before `Number(...)`

Issue: Rust's `str::parse::<u32/u64/i64>()` accepts an optional leading `+` sign (and `i64`
accepts `-`). TS's `isAllDigits` regex rejects any non-`[0-9]` character. The date is split on
`-` and the time on `:`, so a `+` can appear at the start of a field.

Failure scenario: a validly-signed Validity string `"+2099-01-01T00:00:00.000000000Z"` (or
`"2099-01-01T+00:00:00...Z"`).

- Rust: `"+2099".parse::<i64>()` → `Ok(2099)`; parse continues; year 2099 → far future →
  **accept**.
- TS: `isAllDigits("+2099")` → `false` → `parseRfc3339ToUnixSecs` returns `null` →
  "unparseable Validity" → **reject**.

Result: desktop/FUSE (Rust) accepts a non-canonical timestamp the web client rejects — the
mirror image of the previous finding, and Rust is the lenient side here (mild soundness concern:
Rust admits a non-canonical RFC3339 string). No vector covers it.

Recommendation: make Rust reject the `+`/`-` sign to match TS's digits-only contract — e.g. a
per-field `bytes().all(|b| b.is_ascii_digit())` pre-check (the parser already uses exactly this
guard for the fractional part at line 230), before `.parse()`.

---

## LOW — Year magnitude overflow diverges (`i64` in Rust vs `Number` in TS)

Location: `crates/api-client/src/ipns.rs:217` (`year: i64 = ...parse()`) vs
`packages/sdk-core/src/ipns/index.ts` (`year = Number(yearStr)` after `isAllDigits`).

Issue: Rust rejects a year string that overflows `i64` (≥ 20 digits → `parse` `Err` → `None`).
TS's `Number(yearStr)` never fails on magnitude, so an over-long all-digit year passes every
validation and produces a huge far-future expiry.

Failure scenario: signed Validity `"999999999999999999999-01-01T00:00:00Z"` → Rust **reject**
(i64 overflow), TS **accept** (far-future, not expired). Additionally, years beyond `2^53` lose
precision under `Number`, so the exact computed seconds diverge from Rust's `i64` arithmetic
(verdict usually still agrees since both remain "far future," but the value is not bit-identical).

Recommendation: RFC3339 mandates a 4-digit year, and `format_validity_timestamp` only ever emits
4 digits. Enforce it in both languages (`yearStr.length === 4` / `date_part` year segment length
== 4), which closes this divergence and the general non-canonical-year leniency below. At minimum,
reject in TS when `!Number.isSafeInteger(year)`.

---

## LOW — `ValidityType` encoded as a CBOR float/non-integer diverges

Location: TS `packages/sdk-core/src/ipns/index.ts:432-440` vs Rust `crates/core/src/ipns.rs`
(`ValidityType` arm requires `CborValue::Integer`, else `CborEncodingFailed`).

Issue: Rust strictly requires the `ValidityType` CBOR value to be an integer. TS reads whatever
cborg yields and only checks `validityTypeNum !== 0`. A CBOR **float** `0.0` decodes to JS `0`
and passes the gate.

Failure scenario: signed record with `ValidityType` encoded as CBOR float `0.0` → Rust **reject**
(not `Integer`), TS **accept**. Non-conformant encoding, signature-gated, so LOW.

Recommendation: type-check in TS to mirror Rust:

```ts
if (typeof validityType !== 'bigint' && (typeof validityType !== 'number' || !Number.isInteger(validityType))) {
  throw new Error('IPNS record ValidityType is not an integer — fail closed');
}
```

---

## INFO — Test-vector coverage gaps for the divergences above

`tests/vectors/ipns/verify.json` adds expired, wrong-ValidityType(=1), trailing-component, and
impossible-date cases — good. It does **not** cover: duplicate `ValidityType`/`Validity` keys
(MEDIUM #1), leading-`+` numeric fields (MEDIUM #2), year overflow (LOW #3), non-integer
ValidityType (LOW #4), or a missing-ValidityType case (the code path exists in both languages but
is only unit-tested Rust-side, not in the shared oracle). Because these are exactly the inputs
where the two languages disagree, the shared oracle currently cannot detect the regressions.
Recommend adding one vector per case.

---

## INFO — node-codec `fileIv` hex→base64 lock: vector self-consistent, but confirm codec source (out of reviewed diff)

Location: `tests/vectors/node-codec.json` (fileIv values changed from hex to base64;
`expected_file_iv_len_bytes` 12/16 added; `expected_read_body_hex` regenerated).

The change is internally consistent: `"Mo3oQ575VK8KZcAb"` decodes to 12 bytes (GCM, matches
`expected_file_iv_len_bytes: 12`) and `"PIPKEVif5i10uwJJkNceZQ=="` to 16 bytes (CTR, matches 16).
This closes a real hex/base64 domain-confusion risk: the old value `"000102...0b"` is simultaneously
valid hex (12 bytes) and valid base64 (18 bytes), so a hex-vs-base64 decode split would yield a
different IV and silently wrong decryption.

Caveat: the codec **source** (TS + Rust `readBody`/decode) is not in the reviewed diff, so I could
not confirm both languages now decode `fileIv` strictly as base64. Recommend confirming: (a) both
decoders use base64 (not hex) for `fileIv`; (b) base64 padding/url-safe handling is identical
across languages (the CTR vector carries `==` padding); (c) a length check rejects a base64 string
that decodes to the wrong IV length.

---

## CLEAN

- UUID canonical-only tightening has correct parity. Rust `is_canonical_uuid_form`
  (`crates/crypto/src/aes.rs`: len 36, hyphens at 8/13/18/23, `is_ascii_hexdigit` elsewhere) and TS
  `CANONICAL_UUID_RE` (`^[0-9a-fA-F]{8}-{4}-{4}-{4}-{12}$`) accept/reject exactly the same set. The
  `uuid-acceptance.json` oracle (canonical upper/lower accept; simple-32-hex, loose-hyphen, braced,
  `urn:uuid:`, non-hex, too-short, too-long, empty all reject) matches both. No adversarial input
  panics — both are pure shape checks with no arithmetic.
- No unbounded-input / overflow panic risk found in either RFC3339 parser: both fully validate
  before the Hinnant civil-days arithmetic; oversized fields are range-rejected (Rust) or
  range-rejected after a lossless-enough `Number` (TS) rather than panicking. The impossible-date
  guard (reject Feb-30 etc. rather than rolling forward and extending validity) is present and
  identical in both, and is fail-closed-correct.
- `aes.rs` `build_node_aad` ordering is sound: kind/role range checks and the canonical-UUID
  pre-check all run before `Uuid::parse_str`, so the parse only ever sees canonical input.
