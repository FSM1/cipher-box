# Phase 57: API CID and Provider Hardening and Module Dedup - Context

**Gathered:** 2026-06-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Make `apps/api` IPFS CID-handling defense-in-depth consistent, and de-duplicate the
IPFS/unpin module graph. Four findings, all surfaced by the Phase 50 review/`/simplify`
(WR-02, WR-05, IN-04, + the unpin-primitive reuse note) and **deferred** because the
affected files were outside Phase 50's confirmed fix scope.

**Requirement:** HARD-08. **Depends on:** Phase 50 (unpin-integrity baseline).

Two findings are correctness/defense-in-depth (CID validation, URL encoding); two are
tech-debt dedup (provider module, unpin primitive). No new capabilities.

**No open design decisions** — every fix has a locked direction from the source todos +
ROADMAP; this CONTEXT records them for the planner. (Discussion confirmed nothing was
genuinely gray; the only latitude is file placement, left to the planner.)

</domain>

<decisions>
## Implementation Decisions

### CID validation consistency (WR-02)

- **D-01:** Extract the **existing** `UnpinDto` regex into a single shared constant and
  apply it — plus `@MaxLength(255)` — to `RegisterCidDto.cid`. The current
  `UnpinDto.CID_REGEX` is `/^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$/` and already
  covers **CIDv0 (`Qm…` 46 chars) AND CIDv1 (`b…` base32)**. `RegisterCidDto` currently
  uses the looser `/^(Qm…{44,}|b[a-z2-7]{58,})$/` with **no** `@MaxLength` — change the
  CIDv0 branch `{44,}`→`{44}` to match unpin, and add `@MaxLength(255)`.
- **D-02:** The system **uses CIDv1** — `LocalProvider` adds with `?cid-version=1`
  (`local.provider.ts:49`), so new uploads are CIDv1 `bafk…`. The CIDv1 branch
  (`b[a-z2-7]{58,}`, open length, capped by `@MaxLength(255)`) MUST stay. Do **not**
  collapse to a CIDv0-only regex.
- **D-03:** Keep the **regex** approach (the established IN-02 pattern in `unpin.dto.ts`).
  Do NOT introduce a `multiformats`-based `@IsCid()` validator — over-engineering for a
  "make the two DTOs consistent" hardening pass.

### Provider URL encoding (WR-05)

- **D-04:** In `LocalProvider`, encode every CID interpolated into a Kubo query string —
  `pin/rm?arg=`, the symmetric `pin/add` path, **and** `cat?arg=` (`local.provider.ts:87`,
  `:127`, and the add path). Use `URLSearchParams` (preferred) or `encodeURIComponent`.
  Rationale: DB-sourced CIDs reach this path from `drainRow` (`row.cid`) and `guardedUnpin`
  (`pinned_cids`/`pending_unpins` rows), whose register-cid origin was only loosely
  validated before D-01 — the unpin path must not depend on every upstream writer being
  airtight. Pairs with D-01 for defense-in-depth.

### Provider module dedup (IN-04)

- **D-05:** Extract a leaf `IpfsProviderModule` —
  `@Module({ imports: [ConfigModule], providers: [IPFS_PROVIDER], exports: [IPFS_PROVIDER] })`.
  Import it from `IpfsModule`, `VaultModule`, and `PendingUnpinModule`; remove the three
  duplicated `IPFS_PROVIDER` factory definitions and default-URL strings.
- **D-06:** Delete/correct the misleading IN-04 "accepted circular-dependency" comments in
  all three modules. The factory depends only on `ConfigService` (a leaf), so a shared
  provider module creates **no** cycle. The real cycle is `IpfsModule → VaultModule`, which
  is orthogonal to where `IPFS_PROVIDER` is provided.

### Shared unpin primitive (reuse)

- **D-07:** Extract two shared primitives and route all three unpin sites through them:
  - `withCidLock(cid, fn)` — acquires `pg_advisory_xact_lock(hashtext($1)::bigint)` with the
    **existing INT_MIN-safe** key derivation, runs `fn` inside the lock.
  - `refcountAndMaybeUnpin(manager, cid)` — rechecks refcount, unpins when zero, deletes the
    outbox row.
  Sites: `guardedUnpin` main transaction, `guardedUnpin` post-commit delete, and `drainRow`
  in the pending-unpin processor. **Mechanism is the existing advisory-lock primitive** — this
  is consolidation, NOT a new locking choice. (Drift already bit once: the INT_MIN `abs()` fix
  had to be hand-propagated across the 3 sites.)

### Cross-cutting

- **D-08 (api:generate):** Run `pnpm api:generate` and commit the regenerated client **iff**
  the `RegisterCidDto` change alters the OpenAPI spec (adding `@MaxLength(255)` may add a
  `maxLength` to the spec). Verify the spec diff after the DTO change; the pre-commit hook
  `check-api-client.sh` enforces staging the regenerated client alongside API changes.

### Claude's Discretion

- File placement of the shared `CID_REGEX` constant (e.g. a small `cid.constants.ts` under
  `apps/api/src/ipfs/dto/` or `ipfs/`) and of the `withCidLock`/`refcountAndMaybeUnpin`
  helpers (a shared location both `vault.service.ts` and `pending-unpin.processor.ts` import).
- `URLSearchParams` vs `encodeURIComponent` exact form.

### Folded Todos

All four ARE the phase scope (the ROADMAP absorbed them):

- **`2026-06-19-register-cid-dto-validation-inconsistency.md`** (WR-02) → D-01, D-02, D-03.
- **`2026-06-19-local-provider-unescaped-cid-in-pin-url.md`** (WR-05) → D-04.
- **`2026-06-19-extract-leaf-ipfs-provider-module.md`** (IN-04) → D-05, D-06.
- **`2026-06-19-extract-withcidlock-shared-unpin-primitive.md`** → D-07.

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope (folded todos — file/line-level fix directions)

- `.planning/todos/pending/2026-06-19-register-cid-dto-validation-inconsistency.md`
- `.planning/todos/pending/2026-06-19-local-provider-unescaped-cid-in-pin-url.md`
- `.planning/todos/pending/2026-06-19-extract-leaf-ipfs-provider-module.md`
- `.planning/todos/pending/2026-06-19-extract-withcidlock-shared-unpin-primitive.md`

### Source review

- `.planning/phases/50-ipfs-ipns-data-integrity-fixes/50-REVIEW.md` — WR-02, WR-05, IN-04 origins (the unpin-integrity baseline this hardens)

### Target files

- `apps/api/src/ipfs/dto/unpin.dto.ts` — the existing shared-able `CID_REGEX` (v0+v1) + `@MaxLength(255)` template
- `apps/api/src/ipfs/dto/register-cid.dto.ts` — the loose regex to bring into line
- `apps/api/src/ipfs/providers/local.provider.ts` — pin/add, pin/rm, cat URL construction
- `apps/api/src/ipfs/ipfs.module.ts`, `apps/api/src/vault/vault.module.ts`, `apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts` — triplicated `IPFS_PROVIDER` + IN-04 comments
- `apps/api/src/vault/vault.service.ts` (`guardedUnpin`), `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts` (`drainRow`) — the 3 unpin sites

### Project docs

- `CLAUDE.md` — API workflow (run `pnpm api:generate` after DTO/controller changes; commit regenerated client)

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- **`UnpinDto.CID_REGEX`** (`apps/api/src/ipfs/dto/unpin.dto.ts:7`) — already the correct
  v0+v1 regex with `@MaxLength(255)`. D-01 extracts and reuses it; no new regex to design.
- **`pg_advisory_xact_lock(hashtext($1)::bigint)` + INT_MIN-safe key** — already implemented
  inline at the 3 unpin sites (Phase 42/50). D-07 consolidates, doesn't reinvent.

### Established Patterns

- **IN-02 regex-based CID validation** via `class-validator` `@Matches` — the existing,
  intended pattern. Stay on it (D-03).
- **NestJS leaf module + DI token** — `IPFS_PROVIDER` is a factory provider keyed off
  `ConfigService`; standard leaf-module extraction (D-05).
- **api:generate discipline** — DTO changes that alter the OpenAPI spec require regenerating
  and committing `@cipherbox/api-client`; `check-api-client.sh` pre-commit guard enforces it.

### Integration Points

- The shared `CID_REGEX` constant is imported by both `unpin.dto.ts` and `register-cid.dto.ts`.
- `IpfsProviderModule` is imported by 3 feature modules.
- `withCidLock`/`refcountAndMaybeUnpin` are imported by `vault.service.ts` and the
  pending-unpin processor.

</code_context>

<specifics>
## Specific Ideas

- "Make `RegisterCidDto` validate exactly like `UnpinDto`" — the unpin DTO is the reference.
- "The unpin path must not trust upstream validation" — encode at the provider boundary (D-04)
  even though the regexes currently happen to exclude query-significant chars (latent, not yet
  exploitable).

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

### Reviewed Todos (not folded)

- `2026-06-20-ipns-publish-validate-embedded-sequence-without-cas.md` and
  `2026-06-20-ipns-resolve-verify-coverage-and-web-sdk-dedup.md` → **Phase 58** (IPNS
  Signature-Verify Coverage), not 57.
- `2026-06-20-cargo-lock-sync-precise-vs-workspace.md` → CI/release track, not this API phase.

</deferred>

---

_Phase: 57-api-cid-and-provider-hardening-and-module-dedup_
_Context gathered: 2026-06-22_
