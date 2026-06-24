# Phase 60: IPNS Verification Cross-Layer Closeout — Context

**Gathered:** 2026-06-24
**Status:** Ready for planning
**Source:** Interactive discussion + two recon workflows (migration mechanics + degraded-path/producer audit)
**Requirement:** HARD-11

<domain>

## Phase Boundary

Phase 60 converts IPNS resolution to a **strict, fail-closed, zero-knowledge integrity model** across every layer, and recovers per-operation verification CPU on the API hot path. It folds three work streams plus a strategic simplification the team chose during planning:

- **Stream A — Strict / no-legacy verify cutover (folded in from the strict-equality-cutover todo, expanded by recon).** Remove every degraded-acceptance branch (legacy/no-signature tolerance, first-publish embedded-0 skew allowance, NULL-record tolerance) across Rust, TypeScript, and the API; unify all first-publish producers to embed sequence `1`; add resolve-side record-expiry enforcement; regenerate the cross-language verify vector.
- **Stream B — Verified-resolve coverage everywhere.** Route all remaining unverified `resolve_ipns` call sites (desktop Tauri shell + the `crates/sdk` bypasses) through a verified resolver with scoped fail-closed parity.
- **Stream C — API hot-path verify caching.** Short-circuit redundant signature verification of DB-authoritative records on the publish/resolve hot path while still fully verifying externally-sourced / DHT records, with a measured per-op cost recovery.

**Strategic context (drives the approach):** There is **no production instance** and staging data is explicitly disposable. The team will **wipe staging** as part of the cutover. Vault identity self-bootstraps on next login (all IPNS keys are deterministically derived from the Web3Auth private key, not stored server-side), so a wipe produces zero legacy / embedded-0 records and is non-destructive to a returning key-holder's identity. This makes a clean strict cutover strictly simpler than a gated record migration — there is no live population to migrate, no drain pass, and no skew window to maintain.

</domain>

<decisions>

## Implementation Decisions

### Approach

- **D-01 — Strict / no-legacy rip-out, not a gated migration.** Do the full cutover: remove all degraded-acceptance branches, unify producers, regenerate the vector, and **wipe staging**. Do NOT build record-migration tooling, a TEE-drain pass, or a forward-compat skew window — the wipe + self-bootstrap removes the population those would serve. Local dev DBs must also be wiped (existing embedded-0 records would otherwise fail-closed until republished).
- **D-12 — Land the cutover cross-layer in lockstep.** The Rust verify, TS resolve, API service/codec, and the cross-language vector strict changes must ship together; the embed-1 producer changes must ship together with strict verify and the staging wipe so no embedded-0 record exists when strict verify goes live. This is the CR-01 lesson (never flip one layer or flip before the source is unified).

### Stream A — Strict verify cutover

- **D-02 — Unify ALL first-publish producers to embed sequence `1`.** Nine sites (the two named in the todo plus seven the recon + researcher found; verify each by symbol before editing):
  1. `crates/fuse/src/write_ops/implementation/mkdir.rs:173` (FUSE new folder)
  2. `crates/fuse/src/platform/windows/write_ops.rs:201` (Windows new folder)
  3. `crates/fuse/src/metadata.rs:557` (FUSE bin first publish — `make_bin_record(0)`)
  4. `packages/sdk-core/src/vault/index.ts:44` (SDK vault-key blob)
  5. `apps/web/src/hooks/useAuth.ts:191` (web vault-key blob — fires on every new vault)
  6. `apps/web/src/hooks/useAuth.ts:208` (web root-folder metadata — fires on every new vault)
  7. `apps/web/src/services/vault-settings.service.ts:131` (web vault settings first publish)
  8. `apps/desktop/src-tauri/src/commands/vault.rs:109` (desktop vault-key blob init — researcher addition)
  9. `apps/desktop/src-tauri/src/commands/vault.rs:154` (desktop root-folder init — researcher addition)
- **D-03 — Tighten the API first-publish gate to reject embedded `0`.** `apps/api/src/ipns/ipns.service.ts:279-285` currently accepts embedded ∈ {0n, 1n} on first publish; require it to start at `1` so the source of truth matches the unified producers. (`:356-357` already forces DB sequence `1`.)
- **D-04 — Remove all Rust degraded-acceptance paths.** Delete the all-fields-absent `Ok(None)` legacy branch (`crates/api-client/src/ipns.rs:77-80`); remove the `VerifyError::Legacy` variant (`crates/fuse/src/verify.rs:21-24`, Display `:34-37`) and fold all 9 caller arms (`events.rs`, `metadata.rs` ×3, `publish.rs` ×2, `fs.rs`, `replay.rs` ×2) into their existing fail-closed `Invalid` handling; drop the skew disjunct at `verify.rs:124` to strict `embedded_seq == resp_seq`.
- **D-05 — Remove all TS degraded-acceptance paths.** Delete the legacy `else` fall-through (`packages/sdk-core/src/ipns/index.ts:293-295`) so a record lacking signature fields throws; drop the skew disjunct (`:285-292`) to strict equality.
- **D-06 — Remove all API degraded-acceptance paths.** `parseCachedRecord` returns `null` (→404) when `signed_record IS NULL` (`apps/api/src/ipns/ipns-record.codec.ts:81-82`); stop silently overriding embedded≠DB sequence skew (`:67-75`); remove the nullable-publicKey / cached-signature legacy-enrich branches (`ipns.service.ts:226`, `:494`, `:512-520`). Publish-side verify (`ipns.service.ts:87-89`) is already mandatory/strict and is the anchor — keep it.
- **D-07 — Add resolve-side EOL/expiry enforcement.** Both verifiers currently check signature + binding but not record expiry on resolve; a validly-signed expired record passes today. Add expiry checks to the Rust verifier and route the TS resolve path through the validator (or add an explicit CBOR `Validity` check) so expired records fail-closed.
- **D-10 — Regenerate the cross-language verify vector and tests.** In `scripts/gen-ipns-verify-vectors.ts` reclassify `legacy-absent` → `invalid` and `first-publish-skew` → `invalid` (in the generator, not by hand); regenerate `tests/vectors/ipns/verify.json` via `npx tsx`; update the `crates/fuse/tests/ipns_verify_vectors.rs` classifier (`:88-89`, `:134`) and the affected Rust unit tests (`verify.rs:244-253`, `:268-286`; `api-client/src/ipns.rs:233-238`).

### Stream B — Verified-resolve coverage

- **D-08 — Close the `crates/sdk` unverified bypasses via an `api-client` verified-resolve wrapper.** `crates/sdk/src/registry.rs:170` and `crates/sdk/src/sync.rs:201` call raw `resolve_ipns` with zero verification (accept tampered CIDs — broader than the legacy hole). The verified chokepoint currently lives in `cipherbox-fuse`, which the SDK does not depend on; add a verified-resolve wrapper in `crates/api-client` (or another crate the SDK + FUSE + desktop all depend on) and route these sites through it.
- **D-09 — Route the desktop Tauri `resolve_ipns` sites through the verified resolver.** `apps/desktop/src-tauri/src/fuse/prepopulate.rs` (~43/110/177/236) and `apps/desktop/src-tauri/src/commands/vault.rs` (~21/250) — note the researcher corrected these paths from the todo's `src/prepopulate.rs`/`src/vault.rs`. Apply the same per-operation scoped fail-closed posture the FUSE sites use. Verify line numbers by symbol before editing.

### Stream C — API hot-path verify caching

- **D-11 — Recover per-op verification CPU on the publish/resolve hot path.** Implement a safe short-circuit (skip re-verifying DB-authoritative records this server just signed/persisted) and/or a short-TTL verified-record cache keyed by `(ipnsName, sequenceNumber, signature)`. MUST still fully verify externally-sourced / DHT records (someguy resolves) and anything not produced/persisted by this server — no integrity reduction for untrusted inputs. Deliver a measured per-op cost recovery (benchmark/prototype), per `docs/CAPACITY.md` §1.5.

### Claude's Discretion

- Exact crate placement of the shared verified-resolve wrapper (D-08) — `api-client` vs a new shared crate — chosen to minimize dependency churn while letting FUSE, SDK, and desktop all consume it.
- Caching mechanism for D-11 (in-process map vs Redis short-TTL) and the exact short-circuit predicate, provided untrusted/DHT records are always verified.
- Whether to express the lockstep changes as one wave or several, provided D-12's "no embedded-0 record alive when strict verify ships" invariant holds.

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope todos (the three folded streams)

- `.planning/todos/pending/2026-06-23-phase60-ipns-first-publish-strict-equality-cutover.md` — Stream A origin (strict-equality cutover, CR-01 history)
- `.planning/todos/pending/2026-06-22-desktop-resolve-ipns-verified-coverage.md` — Stream B (desktop verified-resolve)
- `.planning/todos/pending/2026-06-23-cache-redundant-ipns-signature-verification-hot-path.md` — Stream C (hot-path caching)

### IPNS verification source of truth

- `crates/fuse/src/verify.rs` — the verify chokepoint, the skew allowance (`:124`), and the Phase-60 deferral note (`:100-130`)
- `crates/api-client/src/ipns.rs` — `verify_ipns_resolve_signature` (`Option<bool>` legacy contract, `:73-80`)
- `crates/core/src/ipns.rs` — record build/sign (`build_cbor_data`, `create_ipns_record`); the sequence is inside the signature-covered CBOR
- `packages/sdk-core/src/ipns/index.ts` — TS resolve verification (legacy else `:293-295`, skew `:285-292`, inline `verifyIpnsSignature` with no EOL `:172-184`)
- `packages/crypto/src/ipns/verify-record.ts` — validator-based verify (publish-path; the EOL-aware verifier to reuse for D-07)
- `apps/api/src/ipns/ipns.service.ts`, `ipns-record.codec.ts`, `ipns.controller.ts`, `entities/folder-ipns.entity.ts` — API resolve/publish/codec + the nullable `signed_record`/`public_key` legacy markers

### Operational + design docs

- `docs/DATABASE_EVOLUTION_PROTOCOL.md` (§ reset, `:260-266`) — documented staging DB wipe procedure
- `docs/CAPACITY.md` §1.5 — hot-path per-op cost re-baseline (Stream C target)
- `apps/web/src/hooks/useAuth.ts` (`:172-231`) — login self-bootstrap (vault re-derivation on empty DB)
- Phase 59 `59-REVIEW.md` (CR-01/CR-02) and `59-VERIFICATION.md` Post-Review Amendment — why the flip was reverted before

</canonical_refs>

<specifics>

## Recon-Verified Change-Site Inventory

Two recon workflows mapped these with file:line precision. The planner should treat this as the task spine and re-verify line numbers by symbol before editing.

### Degraded-acceptance branches to remove (14)

| # | Layer | File:line | Tolerates | Strict change |
| - | ----- | --------- | --------- | ------------- |
| 1 | Rust api-client | `crates/api-client/src/ipns.rs:77-80` | all-3-absent → `Ok(None)` (fail-open) | delete branch (falls through to `Some(false)`); consider `Option<bool>`→`bool` |
| 2 | Rust FUSE verify | `crates/fuse/src/verify.rs:68-72` | `None → Err(Legacy{cid,seq})` | remove `Legacy` arm |
| 3 | Rust FUSE verify | `crates/fuse/src/verify.rs:124` | skew `(resp==1 && embedded==0)` | strict `embedded_seq == resp_seq` |
| 4 | Rust FUSE verify | `crates/fuse/src/verify.rs:138-145` | returns DB `resp_seq` to absorb skew | return becomes natural once strict; clean comment |
| 5 | Rust FUSE | `VerifyError::Legacy` variant `:21-24`/`:34-37` + 9 caller arms (`events.rs:92-105`, `metadata.rs:326-335/477-494/645-654`, `publish.rs:105-125/173-189`, `fs.rs:496-505`, `replay.rs:338-348/467-476`) | warn + proceed on unsigned DB cid | remove variant; fold callers into `Invalid` |
| 6 | Rust SDK bypass | `crates/sdk/src/registry.rs:170`, `crates/sdk/src/sync.rs:201` | raw `resolve_ipns`, no verify at all | route through verified wrapper (D-08) |
| 7 | TS sdk-core | `packages/sdk-core/src/ipns/index.ts:293-295` (+ gate `:218`) | no-signature → warn + return cid | delete else; missing fields throw |
| 8 | TS sdk-core | `packages/sdk-core/src/ipns/index.ts:285-292` | skew disjunct | strict equality |
| 9 | TS sdk-core | `packages/sdk-core/src/ipns/index.ts:172-184` (`verifyIpnsSignature`) | no EOL/expiry on resolve | add expiry / route via validator (D-07) |
| 10 | API codec | `apps/api/src/ipns/ipns-record.codec.ts:81-82` | `signed_record IS NULL` → 200 cid-only | return `null` → 404 |
| 11 | API codec | `apps/api/src/ipns/ipns-record.codec.ts:67-75` | embedded≠DB seq silently overridden | hard error/discard on mismatch |
| 12 | API service | `apps/api/src/ipns/ipns.service.ts:279-285` | first-publish embedded ∈ {0n,1n} | drop `0n` (D-03) |
| 13 | API service | `ipns.service.ts:226`, `:494`, `:512-520` | nullable pubkey/signedRecord enrich | require non-null; remove enrich |
| 14 | Vector | `tests/vectors/ipns/verify.json` + `crates/fuse/tests/ipns_verify_vectors.rs:88-89/134/164` | `legacy-absent`→legacy, `first-publish-skew`→valid | reclassify both → invalid; regen (D-10) |

### Producers to unify to embed `1` (9) — see D-02

mkdir.rs:173, windows/write_ops.rs:201, metadata.rs:557, sdk-core/vault/index.ts:44, useAuth.ts:191, useAuth.ts:208, vault-settings.service.ts:131, commands/vault.rs:109, commands/vault.rs:154. (FUSE replay child-folder `replay.rs:628` already embeds 1; all file/folder-update paths use `seq+1` and are out of scope.) Note: the researcher reported several inventory line numbers shifted (e.g. api-client `Ok(None)` at :78-79, `Legacy` arm at :69-71, TS legacy else block at :293-295 with warn at :294, codec change is ADDING `if (!signedRecord) return null`); see 60-RESEARCH.md for the verified line set.

### Facts that bound the plan

- The embedded sequence is inside the signature-covered CBOR; changing it requires re-signing (Ed25519 key). The API server holds no plaintext key and cannot re-sign — but with the wipe + self-bootstrap, no re-sign migration is needed.
- No producer emits V1-only or unsigned records (all route through `create_ipns_record` / `createIpnsRecord` with `v1Compatible:true`). "Legacy" is purely a resolve-side tolerance artifact — removing it cannot break a producer.
- Publish-side verify (`ipns.service.ts:87-89`) is already strict and mandatory; it is the anchor the strict regime relies on.
- The `verify.rs:105` comment claiming `next_file_publish_sequence` embeds 0 is stale — `publish.rs:18` returns 1. Trust the producer inventory above, not that comment.

</specifics>

<deferred>

## Deferred Ideas

- Restoring previously-uploaded file content after a wipe — out of scope; login republishes an empty root, and staging content is disposable.
- `tee_key_state` re-seed verification after wipe — operational checklist item for the operator, not a code task.

</deferred>

---

_Phase: 60-ipns-verification-cross-layer-closeout-desktop-and-api_
_Context gathered: 2026-06-24 via interactive discussion + recon workflows_
