# Phase 58: IPNS Signature-Verify Coverage - Context

**Gathered:** 2026-06-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Make IPNS signed-record verification **complete and safe-by-default** across both
languages. This finishes the Phase 51 / PR #529 verification story:

1. Bind every resolved record to its embedded CID/sequence by decoding the signed
   CBOR `data` and comparing it to the response's `cid`/`sequence` (closes the
   swap gap on both Rust and JS).
2. Fold verification into a single Rust `resolve_ipns_verified` chokepoint so all
   ~9 resolve sites are safe-by-default (today only 1 of them verifies).
3. Validate the embedded publish sequence even when CAS (`expectedSequenceNumber`)
   is omitted, without regressing the non-CAS publish paths.
4. De-duplicate the web vs sdk-core resolve/verify copies.
5. Add shared cross-language verify test vectors.

This phase clarifies **HOW** to implement the above (failure-mode posture, rollout
strictness, vector coverage). The WHAT and the 4-plan/2-wave structure are fixed by
ROADMAP.md and the two source todos. New capabilities are out of scope.

</domain>

<decisions>
## Implementation Decisions

These are runtime-behavior / security-posture decisions made with the owner. They
are LOCKED — do not re-litigate during research or planning.

### Resolve-side failure posture (Plan 58-01)

- **D-01 — One verified chokepoint, all sites:** Introduce a Rust
  `resolve_ipns_verified` wrapper that resolves **and** verifies in one place, and
  route all ~9 resolve sites through it (folder-meta refresh, file-pointer resolve,
  bin metadata, three-way remote-merge, parent-IPNS merge, sequence-cache resolves,
  plus the existing folder-key descent). New Rust resolve sites are safe-by-default
  thereafter. JS already funnels through a single `resolveIpnsRecord` chokepoint —
  keep that property.
- **D-02 — Fail-closed, scoped per-operation:** On a verification failure, refuse
  the unverified CID but **fail only that operation**, not the whole mount. The
  affected folder/file/merge surfaces an error or holds its previous (stale) state;
  the IPNS poll loop is not wedged, so the next 30s poll **self-heals** once a good
  record is returned. Rationale: a verify failure is never user-fixable (it means
  tampering or a verifier bug), so "log a warning and proceed" is useless — the
  honest choice is refuse-vs-silently-trust, and silently trusting bad data is
  unacceptable. Per-operation scoping avoids turning a "Medium" defense-in-depth
  check into an availability cliff.
- **D-03 — Security boundary stays hard fail-closed:** The folder-key-descent site
  (audited as T-51-07 in Phase 51) keeps its existing hard fail-closed behavior — a
  swapped folder key would let an attacker redirect the whole subtree.
- **D-04 — Legacy records still allowed (D-03 / all-absent):** Records with **all
  three** signature fields absent (legacy, pre-signing) continue to be allowed and
  flagged `signatureVerified=false`. This phase does not break legacy records.
- **D-05 — Unified Rust↔JS posture:** Both languages end up fail-closed on
  invalid/partial. This intentional convergence de-risks the 58-03 dedup (the two
  implementations become behaviorally identical, so collapsing them is safe).
- **D-06 — Metric is a side effect, not the response:** A verification-failure
  counter/telemetry signal may be emitted for operator observability, but it is NOT
  the primary handling — the primary handling is the scoped fail-closed in D-02.

### CID/sequence-binding mismatch (Plan 58-01)

- **D-07 — Mismatch == verification failure:** A valid signature whose decoded CBOR
  `data` embeds a `cid`/`sequence` that does **not** match the response's
  `cid`/`sequenceNumber` is classified **identically to an invalid signature**, and
  therefore gets the D-02 fail-closed-scoped handling. A mismatch is a strong tamper
  signal (a genuinely-signed record being misrepresented), so it must not be a
  softer "warn and proceed" path.
- **D-08 — Signed value is the source of truth:** When binding succeeds, the
  signed/embedded `cid`/`sequence` is authoritative; the response field is trusted
  only when it matches. Apply the binding + comparison **symmetrically in Rust and
  JS**. (Today neither side decodes the CBOR to compare — this is net-new on both.)

### Non-CAS embedded-sequence validation (Plan 58-02)

- **D-09 — Exact validation rule (enforced even when CAS is omitted):**
  - No existing DB row (first publish): allow embedded ∈ {0, 1}; reject anything
    higher (this is the poison case that wedges a name).
  - Existing DB row at sequence `N`:
    - embedded `= N` → allow, **idempotent republish, do NOT increment the DB
      sequence** (this is the TEE's 6-hour re-sign path and must not break).
    - embedded `= N+1` → allow, increment DB to `N+1`.
    - embedded `< N` → reject (rollback / replay).
    - embedded `> N+1` → reject (wild jump — the wedge poison).
- **D-10 — Enforce directly (hard reject), gated on enumeration + E2E:** Ship D-09
  as a hard reject in this phase. 58-02 MUST first enumerate **every** publish path
  that omits `expectedSequenceNumber` (desktop `vault.rs` init, per-file IPNS,
  file-pointer, bin metadata) and prove each one signs `DB+1` (or equal-idempotent),
  then ship behind the full SDK E2E gate. Rationale: this exact class of tightening
  broke 48/89 SDK E2E tests previously, so any regression will surface loudly in the
  same gate — no shadow/observe phase needed for a Low-severity gap.

### Shared cross-language verify vectors (Plan 58-04)

- **D-11 — One shared JSON fixture, expanded case set:** A single shared JSON vector
  file (co-located following the existing `crates/crypto/tests/cross_language.rs`
  convention) with cases: **valid, tampered-sig, name-mismatch, cid-swapped,
  seq-mismatch, partial-fields (downgrade vector), legacy-absent**. The expanded set
  (beyond ROADMAP's original 4) covers every posture decision above — partial-fields
  and seq-mismatch are now security-load-bearing.
- **D-12 — Required CI gate (for free):** The vectors are consumed by the **existing**
  `cargo test` (Rust) and sdk-core vitest suites, both already run in CI. A vector
  mismatch therefore fails an already-required check — no separate/advisory gate.
  Catching silent Rust↔JS byte-construction drift is the whole point.

### Web/sdk-core dedup (Plan 58-03)

- **D-13 — Web imports sdk-core, deletes its copies:** `apps/web/src/services/ipns.service.ts`
  imports `resolveIpnsRecord` from `@cipherbox/sdk-core` (injecting the web axios
  instance via the `SdkContext`/`ctx` arg the function already accepts) and deletes
  its local `verifyIpnsSignature` + `resolveIpnsRecord` duplicates. **Preserve** the
  web `withPerf('ipns:resolve', …)` wrapper and the ctx/axios injection. The unified
  fail-closed posture (D-05) is what makes this collapse behaviorally safe.

### Claude's Discretion

Left to research/planning (not owner decisions):

- Exact `resolve_ipns_verified` API shape / return type and how callers thread the
  verdict.
- CBOR decode approach/library on the Rust and JS sides.
- The precise per-operation "stale vs error" UX surface for a scoped failure (D-02).
- Fixture file path/format details (within the `cross_language.rs` convention).
- Telemetry/metric plumbing for D-06 (FUSE-side observability is thin today; do not
  block on it — the metric is optional, the scoped fail-closed is not).

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase source / scope todos

- `.planning/todos/pending/2026-06-20-ipns-resolve-verify-coverage-and-web-sdk-dedup.md`
  — defines the resolve-side coverage gap (#1), web/sdk-core dedup (#2), shared test
  vectors (#3), and the PR #529 CBOR cid-binding residue. The authoritative scope for
  Plans 58-01, 58-03, 58-04.
- `.planning/todos/pending/2026-06-20-ipns-publish-validate-embedded-sequence-without-cas.md`
  — defines the non-CAS embedded-sequence gap and the 48/89-regression caution. The
  authoritative scope for Plan 58-02.
- `.planning/REQUIREMENTS.md` — requirement **HARD-09** (this phase).
- `.planning/ROADMAP.md` §"Phase 58: IPNS Signature-Verify Coverage" — goal, plan
  list, wave structure, verification gate.

### IPNS / verification source (current behavior — confirmed by scout)

- `crates/api-client/src/ipns.rs:66-125` — `verify_ipns_resolve_signature`; returns
  `Ok(None)` (all-absent/legacy), `Ok(Some(true))` (valid+name-match),
  `Ok(Some(false))` (partial/invalid/name-mismatch, fail-closed), `Err`. Does NOT
  decode CBOR `data` to bind cid/sequence today.
- `crates/fuse/src/replay.rs:333,341-364` — `resolve_folder_key`: the ONLY site that
  currently verifies (T-51-07). Keep hard fail-closed (D-03).
- Unverified Rust resolve sites to route through the new wrapper:
  `crates/fuse/src/events.rs:89` (spawn_metadata_refresh),
  `crates/fuse/src/fs.rs:490` (FilePointer async resolve),
  `crates/fuse/src/publish.rs:95` (resolve_sequence),
  `crates/fuse/src/publish.rs:137` (resolve_sequence_strict),
  `crates/fuse/src/metadata.rs:329` (remote_merge),
  `crates/fuse/src/metadata.rs:444` (bin IPNS resolve),
  `crates/fuse/src/metadata.rs:607` (file-metadata IPNS resolve),
  `crates/fuse/src/replay.rs:469` (parent-IPNS merge).
- `packages/sdk-core/src/ipns/index.ts:171-261` — `verifyIpnsSignature` +
  `resolveIpnsRecord` (the JS chokepoint; throws on invalid/partial; allows+flags
  legacy; no CBOR cid binding today).
- `apps/web/src/services/ipns.service.ts:139-231` — web duplicate of the above with a
  `withPerf` wrapper + `ctx.axiosInstance` injection (delete per D-13).
- `apps/api/src/ipns/ipns.service.ts:258-297` — server S1 embedded-sequence check
  (`publishRecord`/`upsertFolderIpns`); the sequence branch runs ONLY when
  `expectedSequenceNumber !== undefined` (line ~277); DB sequence inits to `'1'` on
  create, increments by 1 on update.
- `packages/sdk-core/src/file/index.ts:41-48,114-182` and
  `packages/sdk-core/src/folder/registration.ts:219-329` — publish payload paths;
  file IPNS records omit `expectedSequenceNumber` (CAS skipped) — must be enumerated
  for D-09/D-10.
- `crates/crypto/tests/cross_language.rs` — the existing cross-language test-vector
  pattern to mirror for D-11/D-12.

### Project docs (IPNS record + metadata schemas)

- `docs/FILESYSTEM_SPECIFICATION.md` — encrypted filesystem, IPFS/IPNS metadata model.
- `docs/METADATA_SCHEMAS.md` — IPNS record / folder-metadata schemas.

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `verify_ipns_resolve_signature` (Rust) and `verifyIpnsSignature`/`resolveIpnsRecord`
  (sdk-core) already exist and implement the D-02/D-03/D-04 signature classification.
  The phase wraps/extends them — it does not start from scratch.
- The JS `resolveIpnsRecord` already accepts a `SdkContext`/`ctx` arg for axios
  injection — this is the seam the web app uses for D-13 (no new plumbing needed).
- `crates/crypto/tests/cross_language.rs` is a working precedent for shared
  cross-language fixtures (D-11/D-12).

### Established Patterns

- **"DB CID is authoritative; signature verification is defense-in-depth (Medium)."**
  This is the trust-model anchor for the whole phase. Verification is a backstop
  against a tampering server / MITM, not the primary trust root — which is why D-02
  uses *scoped* fail-closed (not whole-mount) and why legacy records (D-04) stay
  allowed.
- IPNS sync is **30s polling** (no push) — this is what makes the D-02 scoped
  failure self-healing.
- TEE republishes IPNS every 6 hours by re-signing the same record without bumping
  the sequence — D-09's `embedded = N` idempotent-no-increment branch exists
  specifically to protect this path.
- Partial-signature-fields fail closed (shipped in PR #529 on both Rust and JS) —
  D-11 must keep a `partial-fields` vector to prevent regressing that downgrade
  defense.

### Integration Points

- New `resolve_ipns_verified` wrapper sits between the api-client `resolve_ipns` and
  the ~8 FUSE call sites listed above.
- D-07/D-08 CBOR binding plugs into both `verify_ipns_resolve_signature` (Rust) and
  `resolveIpnsRecord` (sdk-core).
- D-09/D-10 validation plugs into `apps/api/src/ipns/ipns.service.ts` `publishRecord`
  → `upsertFolderIpns`, with E2E coverage added for every non-CAS publish path.

</code_context>

<specifics>
## Specific Ideas

- The verification gate for the whole phase (from ROADMAP): **full SDK E2E suite
  (local; redis 6380), apps/api specs, and `cargo test`** must pass. D-10 in
  particular is gated on full SDK E2E because of the prior 48/89-test regression.
- Cross-language interop bug class to defend against (D-11/D-12): each side's tests
  independently hard-code the `"ipns-signature:"` prefix + signed-bytes construction;
  without a shared vector, byte-construction drift passes both suites while making
  Rust and JS silently disagree on validity.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope. (The two source todos above are the
phase's own scope, already folded by the ROADMAP; the remaining `todo.match-phase`
hits were keyword-noise — search index, logger redaction, etc. — and are unrelated
to IPNS signature verification.)

</deferred>

---

_Phase: 58-ipns-signature-verify-coverage_
_Context gathered: 2026-06-22_
