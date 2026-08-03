---
name: crypto-privacy-review
description: Review code for cryptographic security, generate test cases and edge cases
allowed-tools:
  - Read
  - Glob
  - Grep
  - Bash
  - Write
  - Task
  - AskUserQuestion
---

<objective>

Review produced code through the lens of a cryptography and security testing expert. This command evaluates cryptographic implementations, validates security assumptions, and generates comprehensive test cases and edge cases.

**This command is NOT overwritten by GSD updates.**

**Use when:**

- After implementing cryptographic features
- Before merging security-critical code
- When you want test case ideas for crypto operations
- To validate security assumptions in the design

**Creates:**

- A review report returned directly to the caller (orchestrator) — inline in
  context, or as a temporary file under the session scratchpad when it is too
  large to inline
- Test case suggestions (inline)

Review reports are working artifacts, never repo content: do NOT write them
into the repository tree and do NOT commit them.

</objective>

<execution_context>

## Project Security Rules

Normative sources: `blueprint/core.md` (primitives, KDF edge catalog, wire
format, KAT regime) and `CONTEXT.md` (ubiquitous language). AGENTS.md "Critical
Security Rules" restates them; where they disagree, the blueprint wins.

- Never store `privateKey` or any seed in localStorage/sessionStorage
- Never log sensitive keys or seeds
- Never send unencrypted keys to the server — the server is zero-knowledge
- All crypto lives in `crates/core`; TypeScript has no codec or crypto of its own
- Nothing derives a key outside the frozen KDF edge catalog
- Every resolved record passes the adoption gate; a failure is a fail-closed trust violation, never mere staleness
- Zeroize at the terminal owner only — a callee must not zero a caller-owned buffer
- Encode/decode fail-closed symmetry: wherever decode hard-rejects an invariant, the matching encode path returns `Err` under a release-active check, never `debug_assert!`/`assert!`

## Cryptographic Standards

| Algorithm                                              | Use Case                     | Notes                                                                     |
| ------------------------------------------------------ | ---------------------------- | ------------------------------------------------------------------------- |
| XChaCha20-Poly1305                                     | Sealing                      | 24-byte nonce; sealed bodies, structures, content bytes                   |
| BLAKE3 `derive_key` / `keyed_hash`                     | Key derivation               | The whole edge catalog; ids are fixed-length message input, never context |
| RFC 9180 HPKE, X25519-HKDF-SHA256 + XChaCha20-Poly1305 | Sealing to a person          | Base mode for grant blobs and mailbox; auth mode for HPKE-to-self records |
| X25519 ECDH                                            | Pairwise secrets             | Blinded tags, writer-pseudonym derivation                                 |
| secp256k1 ECDSA, RFC 6979                              | Identity signing             | Grant-set commitment, subkey binding, re-point object                     |
| Ed25519                                                | Pseudonym and record signing | Structure signatures; IPNS records                                        |
| Deterministic CBOR, RFC 8949 §4.2                      | Wire format                  | DAG-CBOR blocks; one strictness policy everywhere                         |
| `Vec<u8>` / `Uint8Array`                               | Binary data                  | Never strings for crypto data                                             |

</execution_context>

<process>

## Phase 1: Scope Definition

Use AskUserQuestion:

- header: "Review Scope"
- question: "What should I review?"
- multiSelect: false
- options:
  - "Specific files" — I'll provide file paths or patterns
  - "Recent changes" — Review uncommitted or recent commits
  - "Phase code" — Review code from a specific GSD phase
  - "Full crypto audit" — Comprehensive review of all crypto-related code

**If "Specific files":** Ask for file paths/patterns
**If "Recent changes":** Run `git diff` and `git diff --cached` to identify changed files
**If "Phase code":** Ask which phase, then read the phase's PLAN.md to identify relevant files
**If "Full crypto audit":** Search for crypto-related patterns across codebase

## Phase 2: Code Discovery

Based on scope, identify files to review:

```bash
# Find crypto-related files (crates/core and crates/engine own the crypto)
grep -r -l "seal\|unseal\|derive_key\|keyed_hash\|hpke\|Hpke\|Zeroizing\|privateKey\|publicKey" --include="*.rs" --include="*.ts" crates packages apps | grep -v node_modules | grep -v "/target/"
```

Also search for:

- New or changed KDF edges, structure tags, and AAD construction
- Adoption-gate stages and anything that classifies a gate failure
- Encode paths whose decode counterpart hard-rejects an invariant
- Key material lifetimes: `Zeroizing` owners, borrows, and zeroize calls
- Authentication/authorization
- API endpoints handling secrets

## Phase 3: Security Analysis

For each file/section, analyze through these lenses:

### 3.1 Cryptographic Correctness

- [ ] Primitive matches the role in the `blueprint/core.md` suite table; nothing outside it
- [ ] HPKE auth mode wherever sender authentication is load-bearing (the HPKE-to-self record families) — base mode there is a forgery hole when the recipient half is public by construction
- [ ] Nonces and HPKE ephemerals come from injected entropy, never an RNG called inside core
- [ ] Nonce never reused under the same key
- [ ] AAD binds `(v, id, scope, epoch, structTag)` under the `cipherbox/v2` domain separator, so a downgrade or transplant fails the tag
- [ ] No deprecated algorithms (MD5, SHA1 for security, DES, RC4)

### 3.2 Key Management

- [ ] Every derivation is a frozen KDF edge-catalog edge — no ad-hoc context strings, no inline hashing of a seed
- [ ] Edge inputs use the frozen shape: `keyed_hash(key = derive_key("<edge context>", seed), message = id16)`, ids as fixed-length message input
- [ ] Separation holds: a new edge cannot produce equal output to an existing one for equal inputs
- [ ] Key hierarchy follows the scope/epoch model (scope seed → node seed → read and structure keys; write scope seed → write seed → writeKey and IPNS keypair)
- [ ] Rotation stays an O(1) root cut plus a lazy wave: a fresh random override seed, a history link backward-only, no eager re-encryption of content bytes
- [ ] Stated non-edges stay non-edges (content keys, override seeds, scope seeds at grant cuts are random)
- [ ] Sealing to a person targets the recipient's X25519 encryption subkey, never their identity key
- [ ] Keys never logged or exposed in errors
- [ ] Key material lives in `Zeroizing` owning types; zeroize happens at the terminal owner only, never in a callee that borrows a caller's buffer
- [ ] No hardcoded keys or secrets

### 3.3 Trust Boundaries

- [ ] Client-side sealing before any server transmission
- [ ] Server never receives plaintext or key material
- [ ] Every resolved record passes the adoption gate before adoption — signature verify, commitment verify, structure signatures against committed write pseudonyms, strictly-newer sequence vs floor, epoch at or above the scope floor, unseal success
- [ ] A gate failure is typed as a trust violation, disjoint from malformed/availability errors — never degraded to staleness or a silent retry
- [ ] Floors advance only on an AAD-confirmed unseal or the owner-vouched re-point object, never from a raw blob epoch field
- [ ] IPNS verification takes the Ed25519 public key from the name itself, never a DB column or side channel
- [ ] The republisher stays keyless: re-PUT round-trips foreign signed bytes byte-stable with no key material

### 3.4 Implementation Safety

- [ ] Crypto lives in `crates/core` — no crypto or codec implemented in TypeScript
- [ ] Encode/decode fail-closed symmetry: a decode-side hard reject has a matching release-active encode-side `Err`, following the `crates/core/src/seal/body.rs` `assert_children_unique` convention — `debug_assert!`/`assert!` are stripped in release and let a build sign bytes its own decoder rejects
- [ ] Decoders accept the deterministic CBOR profile only; duplicate keys, non-canonical encodings, and wrong major types reject
- [ ] Unknown fields tolerated, preserved byte-stable, re-emitted canonically on rewrite
- [ ] Purity holds: no clock, no RNG, no I/O in core — entropy, time, and policy enter as parameters
- [ ] `Vec<u8>` / `Uint8Array` for all binary data
- [ ] Constant-time comparison for tags and authentication tokens
- [ ] No sensitive data in error messages
- [ ] No sensitive data in logs
- [ ] Proper error handling (no silent failures in crypto); every rejection names the check that fired
- [ ] New structure tags and KDF edges extend the KAT manifest with accept and reject vectors before merge

### 3.5 Data Flow Security

- [ ] Sensitive data sealed at rest
- [ ] Sensitive data sealed in transit
- [ ] No sensitive data in URLs or query params
- [ ] No seeds or private keys in localStorage/sessionStorage
- [ ] Metadata leakage minimized — the envelope stays kind-uniform, blinded tags leak only blob count

## Phase 4: Generate Test Cases

For each crypto operation found, generate test cases:

### Positive Test Cases

- Normal operation with valid inputs
- Boundary conditions (empty data, max size data)
- Different key types/sizes

### Negative Test Cases

- Invalid key format
- Corrupted ciphertext
- Wrong key for unseal
- Tampered Poly1305 tag
- Truncated ciphertext, and a short or low-order HPKE `enc`
- AAD transplant: wrong `scope`, `epoch`, `structTag`, or `v`
- Base-mode forgery where auth mode is required

### Edge Cases

- Empty plaintext seal
- Very large data (chunking behavior)
- Unicode/binary data handling
- Concurrent seal operations
- Rotation: an epoch-lagged node read backward through history links
- Re-seal at a new epoch under the lazy wave

### Attack Scenarios

- Replay attacks (sequence vs floor)
- Downgrade attacks (`v` bound into the AAD)
- Timing attacks (constant-time operations)
- Key confusion: cross-family transplant between structure tags
- Floor rollback from a raw blob epoch field
- Forward regression: an old-seed holder reaching a newer epoch

## Phase 5: Generate Report

Return the report to the caller (orchestrator). Prefer presenting it directly
in context; if it is too large to inline, write it to a temporary file under
the session scratchpad (e.g. `<scratchpad>/security-review-[timestamp].md`)
and reference that path. Never write the report into the repository tree
(`.planning/` no longer exists) and never commit it.

Report template:

````markdown
# Security Review Report

**Date:** [timestamp]
**Scope:** [what was reviewed]
**Reviewer:** Claude (crypto-privacy-review command)

## Executive Summary

[2-3 sentences on overall security posture]

**Risk Level:** [LOW/MEDIUM/HIGH/CRITICAL]

## Files Reviewed

| File   | Crypto Operations | Risk Level |
| ------ | ----------------- | ---------- |
| [file] | [operations]      | [level]    |

## Findings

### Critical Issues

[Issues that must be fixed before deployment]

### High Priority

[Issues that should be fixed soon]

### Medium Priority

[Issues that represent technical debt]

### Low Priority / Recommendations

[Nice-to-haves and best practices]

## Detailed Analysis

### [File/Component Name]

**What it does:**
[Brief description]

**Crypto operations:**

- [operation 1]
- [operation 2]

**Issues found:**

1. **[Issue Title]**
   - **Severity:** [CRITICAL/HIGH/MEDIUM/LOW]
   - **Location:** [file:line]
   - **Description:** [what's wrong]
   - **Impact:** [what could happen]
   - **Recommendation:** [how to fix]
   - **Reference:** [standard/best practice]

**Positive observations:**

- [what's done well]

---

[Continue for each file/component]

## Test Cases

### [Feature/Component]

#### Unit Tests

```rust
// Accept vector: exact bytes under a fixed key/nonce (or fixed ephemeral), then open
#[test]
fn [component]_accept_[case]() {}

// Reject vector: the check that must fire, named
#[test]
fn [component]_reject_[invalid_input]() {}

// Edge case
#[test]
fn [component]_handles_[edge_case]() {}
```

#### Integration Tests

- [ ] [Test scenario 1]
- [ ] [Test scenario 2]

#### Attack Scenarios to Test

- [ ] [Attack scenario 1] — [how to test]
- [ ] [Attack scenario 2] — [how to test]

## Compliance Checklist

Based on project security rules:

- [ ] No `privateKey` or seed in localStorage/sessionStorage
- [ ] No sensitive keys or seeds logged
- [ ] No unencrypted keys sent to server
- [ ] Only `blueprint/core.md` suite primitives used
- [ ] Every derivation is a frozen KDF edge-catalog edge
- [ ] Adoption gate enforced fail-closed on every resolved record
- [ ] Encode-side release-active `Err` mirrors every decode-side hard reject
- [ ] Zeroize at the terminal owner only
- [ ] Server has zero knowledge of plaintext

## Recommendations Summary

| Priority   | Recommendation   | Effort            |
| ---------- | ---------------- | ----------------- |
| [P0/P1/P2] | [recommendation] | [LOW/MEDIUM/HIGH] |

## Next Steps

1. [Immediate action]
2. [Short-term action]
3. [Long-term consideration]

---

_Generated by crypto-privacy-review command_
_This review is automated guidance, not a substitute for professional security audit_
````

## Phase 6: Present Results

Display summary inline:

```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SECURITY REVIEW COMPLETE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Scope:** [what was reviewed]
**Risk Level:** [overall risk]

## Summary

| Severity | Count |
|----------|-------|
| Critical | [n] |
| High | [n] |
| Medium | [n] |
| Low | [n] |

## Top Issues

1. [Most critical issue]
2. [Second issue]
3. [Third issue]

## Test Cases Generated

[n] test case suggestions across [m] categories

**Full report:** [inline above, or scratchpad path if it was too large to inline]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Use AskUserQuestion:

- header: "Next"
- question: "What would you like to do?"
- options:
  - "View full report" — Display the complete review
  - "Generate test file" — Create a test file with suggested cases
  - "Fix critical issues" — Start addressing critical findings
  - "Done" — End review

</process>

<vulnerability_patterns>

## Common Crypto Vulnerabilities to Check

### Nonce Reuse / Self-Sourced Randomness

```rust
// BAD: a fixed nonce, or one core drew itself
let nonce = [0u8; 24];
// GOOD: fresh per seal, from injected entropy — core owns no RNG
let nonce = entropy.nonce_24();
```

### Missing Sender Authentication

```rust
// BAD: HPKE base mode where the recipient half is public by construction —
// any party who can see it can seal a well-formed record
hpke_seal_base(recipient_enc_pk, aad, plaintext)
// GOOD: auth mode binds the sender's static key
hpke_seal_auth(sender_enc_sk, recipient_enc_pk, aad, plaintext)
```

### Off-Catalog Key Derivation

```rust
// BAD: an ad-hoc context string, id smuggled in as variable context
blake3::derive_key(&format!("cipherbox/v2/node/{id}"), seed);
// GOOD: a catalog edge — id is fixed-length message input
kdf::node_seed(scope_seed, id16);
```

### Encode/Decode Asymmetry

```rust
// BAD: stripped in release — the build signs bytes its own decoder rejects
debug_assert!(children_unique(&children));
// GOOD: release-active, returns Err
assert_children_unique(&children)?;
```

### Over-Eager Zeroization

```rust
// BAD: a callee zeroing a buffer its caller still owns and will reuse
fn seal(key: &mut [u8; 32]) { /* … */ key.zeroize(); }
// GOOD: zeroize at the terminal owner; callees borrow
fn seal(key: &Zeroizing<[u8; 32]>) { /* … */ }
```

### Trust Violation Degraded to Staleness

```rust
// BAD: a failed gate stage becomes a retry, and the record is adopted later
Err(_) => Ok(Adoption::Stale),
// GOOD: fail closed, naming the check that fired
Err(e) => Err(TrustViolation::StructureSignature(e)),
```

### Timing Attacks

```rust
// BAD: early return on mismatch
if a[i] != b[i] { return false; }
// GOOD: constant-time comparison
a.ct_eq(b).into()
```

### Key in Logs/Errors

```rust
// BAD
tracing::debug!(?seed, "derived node seed");
// GOOD
tracing::debug!("node seed derivation failed");
```

</vulnerability_patterns>

<success_criteria>

- [ ] Scope defined and files identified
- [ ] All crypto operations catalogued
- [ ] Each operation checked against security criteria
- [ ] Issues categorized by severity
- [ ] Test cases generated for each crypto operation
- [ ] Report returned to the caller (inline, or scratchpad temp file) — never written to the repo or committed
- [ ] Summary presented to user
- [ ] Next steps offered

**Quality indicators:**

- Findings are specific (file:line, not vague)
- Test cases are implementable (actual code suggestions)
- Recommendations include HOW to fix, not just WHAT's wrong
- False positives acknowledged where uncertain

</success_criteria>
