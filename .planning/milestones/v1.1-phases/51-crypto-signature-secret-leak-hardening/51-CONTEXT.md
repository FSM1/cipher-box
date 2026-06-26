# Phase 51: Crypto-Signature & Secret-Leak Hardening - Context

**Gathered:** 2026-06-19
**Status:** Ready for planning
**Source:** Discuss-phase. Scope is one re-verified captured todo (#5) under requirement HARD-02.
Four implementation forks discussed and locked; the rest are pre-answered by the todo. Todo #15
(web logger redaction + Faro transport) was **removed from this phase** post-discussion — see
Deferred Ideas.

<domain>

## Phase Boundary

Close the three deferred IPNS signed-record findings (S1/S2/S3) from the PR #448 security review,
under requirement **HARD-02**. The server stays a zero-knowledge relay and the **DB remains the
authoritative CID source** — these are defense-in-depth / correctness hardening (all Medium
severity), not High-severity data loss.

In scope:

- **S1** — On IPNS publish, validate the embedded signed-record fields against the DTO
  (`apps/api/src/ipns/ipns.service.ts`).
- **S2** — Make signature verification fail-closed and consistent across web, sdk-core, **and** the
  Rust client; resolve callers honor `signatureVerified`.
- **S3** — Establish + enforce a caller-owns-key zeroization convention across the TypeScript SDK
  and Rust crates (exhaustive — see D-05).

Out of scope: the web logger redaction interceptor + Faro transport wiring (todo #15) — deferred
with end-user logging/monitoring, which is not being implemented yet; any broader IPNS/CRDT redesign
(full CRDT deferred to the CRDT-inbox todo); the HARD-03..06 items (Phases 52–55); and changing the
server's authoritative-CID model. S1's already-shipped embedded-vs-embedded anti-rollback (409) stays
as-is — only the embedded-vs-DTO gap is open.

</domain>

<decisions>

## Implementation Decisions

### S1 — Publish-time embedded-vs-DTO validation

- **D-01 (S1, fork):** Reject (400) on **any** embedded-CID vs `metadataCid` mismatch (strict). For
  sequence, use an **offset-aware** check that tolerates the known first-publish convention (client
  signs seq `0` while the DB stores `'1'`; pre-increment, see `ipns.service.ts:296-297,553-555`) and
  rejects only genuine disagreement. `parseIpnsRecord` is already imported (`:24`) and called in
  `upsertFolderIpns` (`:223-226`), so the embedded values are already in hand.

### S2 — Fail-closed signature verification

- **D-02 (S2, locked by todo):** When a signature is **present but invalid**, fail closed
  everywhere — the web path (`apps/web/src/services/ipns.service.ts:177-205`) must **reject**, not
  `logger.warn` and return the CID. sdk-core already throws (`packages/sdk-core/src/ipns/index.ts:196-219`).
- **D-03 (S2, fork — backward-compat):** When signature fields are **absent** (legacy records
  published before signedRecord was reliably populated), **allow + flag + telemetry**: return the
  CID with `signatureVerified=false` and emit a warn/metric. Do **not** fail closed on missing —
  that risks locking users out of existing vaults, and the DB CID is authoritative. (Future
  tightening to require-signed is a follow-up once all records carry signatures.)
- **D-04 (S2, fork — Rust scope):** **Include the Rust half now.** Add the signature fields to
  `IpnsResolveResponse` (`crates/api-client/src/types.rs:130-137`) and verification in
  `crates/api-client/src/ipns.rs` so S2 is closed across web + sdk-core + Rust consistently. Phase 52
  is desktop-durability, not signature work — do not split S2 across phases.
- Resolve callers must honor `signatureVerified` (today no production caller reads it — only producer
  fns + unit tests). Missing fields are treated **explicitly** (the D-03 allow+flag path), never
  silently skipped.

### S3 — Key zeroization (exhaustive)

- **D-05 (S3, fork):** **Exhaustive sweep.** Establish a documented caller-owns-key convention
  (zeroize at the buffer-owning boundary) and apply it across **all** SDK paths, not just the known
  contradiction. Includes:
  - Reconcile the Phase-44 contradiction: `updateFileMetadata` zeroizes its caller-passed key
    (`packages/sdk-core/src/file/index.ts:369-373`) while `updateFolderMetadataAndPublish` zeroizes
    neither (`packages/sdk-core/src/folder/index.ts:177-242`).
  - Add zeroization to the currently-unprotected sdk-core paths: `ipns/index.ts:39-98`,
    `vault/index.ts:32-80`.
  - Fix the Rust raw-`Vec<u8>` key leaks: `crates/crypto/src/ecies.rs:35-47` (`unwrap_key`),
    `crates/fuse/src/lib.rs:933-938` (`get_folder_key` `.to_vec()`), `:1595-1661`
    (`resolve_folder_key` raw-Vec BFS queue), `:745-747` (`spawn_file_meta_reencrypt`).
  - **Enforcement guard:** add a regression test and/or lint that asserts caller-owns-key on the
    touched paths so the convention does not re-drift (the bounded-vs-exhaustive tradeoff was
    explicitly resolved toward exhaustive *with* a guard).

### Suggested sequencing (planner may refine)

S1 (server-authoritative, ~one function) → S2 (cross-cutting: TS + Rust + every resolve caller) →
S3 (exhaustive zeroization + guard).

### Folded Todos

- **[#5]** `2026-06-13-ipns-signature-storage-review-deferred.md` — S1/S2/S3 IPNS signed-record
  findings (re-verified 2026-06-19, all still open). Maps to D-01..D-05.

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & source findings

- `.planning/security/REVIEW-20260402-172126.md` — original IPNS Signature Storage review (PR #448);
  origin of S1/S2/S3.
- `.planning/todos/pending/2026-06-13-ipns-signature-storage-review-deferred.md` — S1/S2/S3 with current
  line numbers, caveats, and re-verification (2026-06-19). The most important ref for S1–S3.
- `.planning/REQUIREMENTS.md` — HARD-02.
- `.planning/ROADMAP.md` §"Phase 51" — scope checkboxes.

### IPNS / signed records (S1, S2)

- `apps/api/src/ipns/ipns.service.ts` — publish/resolve; embedded-vs-DTO validation target (S1).
- `packages/sdk-core/src/ipns/index.ts` — TS verification (S2); also a zeroization gap (S3).
- `apps/web/src/services/ipns.service.ts` — web resolve path that must fail-closed (S2/D-02).
- `crates/api-client/src/ipns.rs`, `crates/api-client/src/types.rs` — Rust verification + response
  fields to add (S2/D-04).
- `docs/FILESYSTEM_SPECIFICATION.md`, `docs/METADATA_SCHEMAS.md` — IPNS record / signed-record
  structure and metadata schemas.

### Zeroization (S3)

- `packages/sdk-core/src/{file,folder,ipns,vault}/index.ts` — TS key-handling paths.
- `crates/crypto/src/ecies.rs`, `crates/fuse/src/lib.rs` — Rust raw-key paths to harden.

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `parseIpnsRecord` (already imported in `ipns.service.ts:24`) — gives the embedded CID/sequence for
  the S1 D-01 comparison; no new parser needed.
- Rust `Zeroizing` / `ZeroizeOnDrop` are already used widely in the crates — the S3 fix is closing
  the raw-`Vec<u8>` escape hatches, not introducing the pattern.
- Existing per-fn `T-47-01` zeroize comments in the higher-level `sdk` package — model for the
  documented convention to push down into `sdk-core`.

### Established Patterns

- Server DB is the authoritative CID source — S2 stays Medium and the D-03 allow-on-missing path is
  safe because verification is defense-in-depth over an already-trusted CID.
- Pre-increment IPNS sequence convention (client signs `0`, DB stores `'1'` on first publish) — the
  S1 sequence check must be offset-aware (D-01).
- Anti-rollback embedded-vs-embedded 409 already shipped (`ipns.service.ts:222-234`) — S1 adds the
  orthogonal embedded-vs-DTO check, does not replace it.

### Integration Points

- S2 changes the resolve **contract**: callers begin honoring `signatureVerified`. Audit all
  `.cid`/`.sequenceNumber`-only call sites in web + sdk-core (and Rust consumers in `crates/fuse`).
- D-04 touches the Rust client + its consumers (desktop) — expect `crates/api-client` API-surface
  additions and a desktop rebuild; run `pnpm api:generate` if any API DTO changes.

</code_context>

<specifics>

## Specific Ideas

- D-03 future-tightening hook: once all records carry signatures, a follow-up can flip the
  allow-on-missing path to require-signed. Capture as a todo at execution time, not this phase.

</specifics>

<deferred>

## Deferred Ideas

- **Todo #15 — web logger redaction interceptor + Faro transport wiring**
  (`2026-06-18-web-logger-redaction-and-faro-transport-unwired.md`). Removed from Phase 51
  post-discussion: end-user logging/monitoring is not being implemented yet, and the redaction
  interceptor has marginal value with no remote transport (its acceptance requires Faro). Re-defer
  to a future observability/monitoring phase, where it gets folded alongside the Faro work.
- Full CRDT conflict model for IPNS — already tracked in the CRDT-inbox research todo; explicitly out
  of scope here.
- Require-signed (fail-closed on missing signature) — deferred until all records are re-published
  with signatures (see D-03 / Specifics).

</deferred>

---

_Phase: 51-crypto-signature-secret-leak-hardening_
_Context gathered: 2026-06-19_
