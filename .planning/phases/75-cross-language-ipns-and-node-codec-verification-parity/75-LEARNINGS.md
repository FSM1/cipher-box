---
phase: 75
phase_name: "cross-language-ipns-and-node-codec-verification-parity"
project: "CipherBox"
generated: "2026-07-11"
counts:
  decisions: 4
  lessons: 5
  patterns: 3
  surprises: 3
missing_artifacts: []
---

# Phase 75 Learnings: cross-language-ipns-and-node-codec-verification-parity

## Decisions

### Canonical-only UUID acceptance (Option A), enforced identically on both sides

Both `uuidToBytes` (TS) and `build_node_aad` (Rust) accept only the canonical
8-4-4-4-12 hyphenated form and reject simple-32-hex, braced, urn, and loose-hyphen
variants. Locked by the shared `uuid-acceptance.json` oracle.

**Rationale:** A single narrow acceptance domain is far easier to keep in lockstep
across two languages than two independently-lenient ones.
**Source:** 75-05-SUMMARY.md

### Hand-rolled RFC3339 parser mirrored branch-for-branch, no chrono/Date

TS `parseRfc3339ToUnixSecs` mirrors Rust `parse_rfc3339_to_unix_secs` exactly
(Hinnant civil-from-days, leap-aware day-of-month, fail-closed on impossible dates)
rather than delegating to `new Date()` / `chrono`.

**Rationale:** Library date parsers are lenient in language-specific ways (`new Date`
rolls impossible dates forward, extending validity); a shared manual parser is the
only way to guarantee identical verdicts.
**Source:** 75-03-SUMMARY.md

### Encoding-unambiguous KAT samples (base64 with uppercase / `==` padding)

The node-codec `fileIv` KAT samples were chosen so they are valid base64 but invalid
hex, and the test decodes-and-asserts-length rather than just comparing strings.

**Rationale:** A KAT that only compares a sample string can't catch a decoder that
reads the field in the wrong encoding; the decode-and-assert makes the encoding
itself load-bearing.
**Source:** 75-04-SUMMARY.md

### Verification hardening is a `fix`, not a `feat`

Shipped under `fix:` (patch bump) since the phase tightens fail-closed verification
and closes soundness gaps rather than adding user-facing capability.
**Source:** ship-phase 75

## Lessons

### JS `$` matches before a trailing newline — a fixed-width length guard is load-bearing

`/^…$/.test("uuid\n")` returns `true` in JS (no `m` flag) because `$` also matches
immediately before a final `\n`. Rust's `regex`/manual `bytes.len() != 36` check does
not. Any cross-language "same regex" claim must add an explicit length/`\A…\z` guard
or the two sides diverge on trailing-newline input. (Surfaced by CodeRabbit; fixed
with `uuid.length === 36`.)

### cborg defaults to last-wins on duplicate map keys

`cborg`'s `decode` defaults `rejectDuplicateMapKeys: false`, so a signed record with
a duplicate key silently last-wins-decodes while a stricter decoder (Rust) rejects it.
Always pass `{ rejectDuplicateMapKeys: true }` on any security-relevant decode.

### `parse::<T>()` in Rust accepts a leading sign; JS digit-regex does not

`"+2099".parse::<i64>()` succeeds; `/^[0-9]+$/.test("+2099")` fails. Numeric-field
parity needs an explicit ASCII-digit + fixed-width check on the Rust side, not bare
`parse()`.

### A signed-vector oracle can't cheaply express every divergence

Duplicate-map-key and float-vs-integer CBOR encodings can't be produced by a normal
CBOR encoder (it dedups / canonicalizes), so those parity cases are locked with
hand-crafted-bytes unit tests instead of the signed oracle. Reserve the oracle for
cases a conformant signer can actually emit.

### The SDK E2E TEE-republish leg needs the full TEE stack; its failure is orthogonal

`tee-republish.test.ts` fails `tee_key_state is empty` unless the TEE worker + seeded
DB (`cipherbox`, matching `TEE_WORKER_SECRET`) are up. For a non-TEE phase, treat
those 2 failures as a pre-existing infra precondition, not a gate — the 104 IPNS
round-trip tests are the relevant signal.

## Patterns

### Shared JSON oracle, consumed by both a Rust `#[test]` and a TS `it()`

`tests/vectors/*.json` drives paired tests in each language; adding one case (e.g. the
trailing-newline UUID) extends coverage on both sides at once.

### Fixed-width digit helper (`parse_fixed_digits` / `isFixedDigits`)

A tiny "exactly N ASCII digits" helper on each side is the parity-safe primitive for
RFC3339 field parsing — it subsumes leading-sign rejection and overflow rejection.

### Pre-fix review report + authoritative SECURITY.md disposition table

Keep the raw crypto/privacy review as a banner-marked pre-fix assessment and let
`<phase>-SECURITY.md` carry the fixed/deferred/discarded dispositions, so the SECURED
verdict stays unambiguous even as fixes land.

## Surprises

### The parity phase itself still shipped with 4 latent divergences

The crypto/privacy review found duplicate-map-keys, leading-sign, year-overflow, and
float-ValidityType divergences that the original 5 plans + oracle missed — a reminder
that "add a parity oracle" and "achieve parity" are different claims until adversarial
review probes the parser edges.

### The most material gap came from CodeRabbit, not the crypto review

The UUID trailing-newline (JS `$` quirk) was the one genuine soundness gap and it came
from the CLI review pass, after the deeper crypto review — the two passes are
complementary, not redundant.

### Verification hardening surfaced no false-reject regression

Despite tightening five reject paths on the resolve plane, the SDK E2E IPNS round-trip
stayed 104/104 green — real records were already strictly canonical, so the tightening
had zero blast radius on legitimate traffic.
