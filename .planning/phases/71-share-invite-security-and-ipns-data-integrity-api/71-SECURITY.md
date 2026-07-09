---
phase: 71
slug: share-invite-security-and-ipns-data-integrity-api
status: verified
threats_open: 0
asvs_level: 2
block_on: high
created: 2026-07-10
---

# Phase 71 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.
>
> Retroactive audit. Phase 71 hardened the share/invite API (`apps/api/src/shares/`) and
> IPNS publish-integrity path (`apps/api/src/ipns/ipns.service.ts`) across 9 plans: a
> server-side root-ownership gate on `createInvite`/`createShare`, a same-sequence CID
> equivocation guard and first-publish race-to-409 translation on IPNS upsert, a
> widen-only grant merge on invite re-claim, a single-statement bulk-revoke DELETE, a
> `claim_count` CHECK constraint, and a full share-plane field rename
> (descriptor → shareRootIpnsName/encryptedReadKey/encryptedWriteKey) threaded through
> api-client (TS + Rust) and web/sdk consumers.
>
> No `<config>` block (asvs_level / block_on) was present in any of the 9 phase plans.
> Defaulted to **ASVS L2** given T-71-01 is a high-severity Spoofing/Elevation threat on
> an authorization boundary (verification traced both entry points end-to-end, confirmed
> correct placement — before persist, before recipient lookup — with no bypass path).
> **block_on: high** per project default (matches prior phase audits, e.g. Phase 45).

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|----------------|
| client → API (`createInvite`/`createShare`) | untrusted `shareRootIpnsName`/`rootNodeId` cross here; previously copied verbatim with no ownership check | `shareRootIpnsName`, `rootNodeId`, ECIES-wrapped read/write keys |
| client/TEE → API (IPNS publish, `upsertIpnsRecord`) | a validly-signed record could repoint the served CID without advancing the sequence, or two brand-new publishes could race the first INSERT | signed IPNS record, `metadataCid`, embedded sequence number |
| claimer → API (`claimInvite` existing-share merge) | claimer-supplied encrypted keys merged into an existing share; a downgrade would silently strip write access | invite row (server-sourced), claimer-supplied re-wrapped keys |
| owner → API (`revokeForItems`) | caller-scoped bulk revoke; must stay scoped to `sharer_id = caller` (no cross-owner deletion) | list of `ipnsName`s |
| API DTO ⇄ DB column ⇄ api-client (TS + Rust) ⇄ web/sdk consumers | the D-10 full share-plane rename must stay internally consistent across the wire contract, or serialization silently breaks / a vault-domain identifier gets conflated with a share-domain one | renamed DTO fields (`shareRootIpnsName`, `encryptedReadKey`, `encryptedWriteKey`) |
| Rust serde ⇄ API JSON | serde field names must equal the regenerated OpenAPI field names or the Rust client silently fails to deserialize | `crates/api-client/src/shares.rs` structs |
| share descriptor rename ⇄ Windows security descriptor | a blind text rename on "descriptor" could corrupt unrelated WinFsp OS symbols | `security_descriptor`/`SecurityDescriptor` Windows FUSE symbols (must NOT be touched) |
| `share_invites.claim_count` | must never exceed `max_claims` or go negative, even under a raw-SQL race | DB CHECK constraint (unconditional at the DB tier) |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-71-01 | Spoofing / Elevation | `createInvite` / `createShare` root identity | high | mitigate | D-01: server-side `ipns_records` creator-ownership lookup (`ipnsName` + `userId`) before persist, `ForbiddenException` (403) on miss. Verified present at **both** entry points: `share-invite.service.ts:42-47` (`createInvite`) and `shares.service.ts:40-45` (`createShare`, runs fail-fast before the recipient lookup). Unit-tested (`share-invite.service.spec.ts:137-165`). | closed |
| T-71-02 | Elevation | `rootNodeId` (client-asserted) | low | accept | D-02 documented residual: only `shareRootIpnsName` ownership is verified server-side; `rootNodeId` stays client-asserted. Code comments at both gate sites explicitly cross-reference D-02. Ownership ceiling is cryptographic (a sharer can only wrap keys they hold — `resolveShareWriteDescriptor` requires the parent folder's real keys), so a forged `rootNodeId` grant is cryptographically inert. True fix (key-possession challenge) is deferred. See Accepted Risks Log AR-71-01. | closed |
| T-71-04 | Tampering | `upsertIpnsRecord` same-seq branch | medium | mitigate | D-05: HARD-GUARD 400 when incoming CID diverges from stored `latestCid` at equal sequence (`ipns.service.ts:311-325`); same-CID idempotent retries preserved (`isIdempotentRepublish`). Unit-tested (`ipns.service.spec.ts:2111-2137`, Pitfall-4 rewrite). | closed |
| T-71-05 | Denial of Service / Repudiation | first-publish INSERT race | low | mitigate | D-06: Postgres `23505` unique-violation translated to a 409 `ConflictException` instead of an ambiguous 500 (`ipns.service.ts:465-483`). Live-proven end-to-end via sdk-e2e Test 21 (`tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts:367-413`) — two concurrent first publishes of the same new `ipnsName` yield exactly one 200 + one 409 against a real Postgres unique-constraint race. Orchestrator-reported green. | closed |
| T-71-06 | Tampering (data-integrity) | `claimInvite` existing-share branch | medium | mitigate | D-07: widen-only merge — every field write gated on `isWriteUpgrade`/`isGenerationBump` (`share-invite.service.ts:182-215`); a same-level/lower re-claim is a true no-op (no `manager.save`). Preserves T-66-E1 (write authority is presence-derived, never downgraded). Unit-tested including an explicit backstop for the downgrade case (`share-invite.service.spec.ts:312-409`). | closed |
| T-71-07 | Tampering / Elevation | `revokeForItems` DELETE scope | low | mitigate | Single `createQueryBuilder().delete()` scoped to `sharer_id = :sharerId` (`shares.service.ts:184-191`), replacing find+remove; a caller can only delete their own shares. Unit-tested (`shares.service.spec.ts:334-386`). | closed |
| T-71-08 | Repudiation (weak test evidence) | share-invite / shares.controller specs | low | mitigate | D-09: real lifecycle coverage replacing placeholder fixtures — `share-invite.service.spec.ts` (470 lines, D-01/D-07/T-66-E1/T-66-S1/self-claim/expiry/atomic-contention/revoke coverage) + `shares.controller.spec.ts` (368 lines, contract-valid DTO fixtures across all endpoints). | closed |
| T-71-09 | Tampering | `share_invites.claim_count` | medium | mitigate | D-04: inline `CHECK` in the greenfield cutover `CREATE TABLE` (`1750000000000-ApiSchemaCutover.ts:110`) + entity `@Check` decorator (`share-invite.entity.ts:14`) — unconditional at the DB tier, immune to application-logic bypass. | closed |
| T-71-10 | Repudiation / contract drift | renamed DTO ⇄ api-client (TS) | low | mitigate | `pnpm api:generate` regenerated the TS client from the renamed DTOs. Verified: `shareRootIpnsName`/`encryptedReadKey`/`encryptedWriteKey` present in `packages/api-client/src/models/*` and `openapi.json`; zero `DescriptorRef`/`writeDescriptorRef` remnants. | closed |
| T-71-11 | Tampering / contract drift | surgical `rootIpnsName` rename (web/sdk) | medium | mitigate | Compiler-guided rename touched only api-client-typed share fields (`invite.service.ts`, `share.service.ts`, `ShareDialog.tsx`, `sdk-core/share/{grant,navigate}.ts`, `sdk-core/rotation/scope.ts`). Verified the distinct vault/folder-tree `rootIpnsName` identifier is untouched: `vault.store.ts` / `useFolderNavigation.ts` still read `vaultStore.rootIpnsName` (intactness AC confirmed). | closed |
| T-71-12 | Tampering / contract drift | `crates/api-client` serde ⇄ OpenAPI | medium | mitigate | Rust struct fields renamed to `encrypted_read_key`/`encrypted_write_key`/`share_root_ipns_name` with `#[serde(rename_all = "camelCase")]` (`crates/api-client/src/shares.rs:95-119`), matching the regenerated `openapi.json` field-for-field. | closed |
| T-71-13 | Denial of Service (build break) | Windows `security_descriptor` symbols | medium | mitigate | Explicit surgical exclusion verified: `security_descriptor`/`SecurityDescriptor` symbols intact and untouched in `crates/fuse/src/platform/windows/{operations,read_ops,write_ops}.rs`; zero `ShareDescriptor`/`share_descriptor` naming collisions found anywhere in `crates/`. | closed |

_Status: open · closed_
_Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)_

**Threats total: 12 · Closed: 12 · Open: 0**

---

## Unregistered Flags

None. No `## Threat Flags` section was present in any of the 9 phase SUMMARY.md files
(`71-01` through `71-09`), so there is no executor-flagged new attack surface to
cross-reference. A manual scan of the two invite controllers (`InvitesController` at
`/invites`, `ShareInvitesController` at `/shares/invites`) confirms the public-facing
`claimInvite` endpoint requires `JwtAuthGuard` (`invites.controller.ts:109-110`) — the
claimer identity is server-derived from the authenticated session, not client-asserted —
consistent with the existing (pre-Phase-71) auth architecture, not new surface.

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|--------------|------|
| AR-71-01 | T-71-02 | `rootNodeId` remains client-asserted on `createInvite`/`createShare` (D-02). Only `shareRootIpnsName` is server-verified against the `ipns_records` creator marker. This is bounded by a cryptographic ceiling: a sharer can only produce a valid ECIES-wrapped key for content whose real keys they hold, so a forged `rootNodeId` yields a share/invite that is cryptographically inert on the recipient side — not a working elevation. The true fix (persisting `root_node_id` on `vaults` to enable full `(rootIpnsName, rootNodeId)` pair validation) is deferred — it touches the vault-init write path and was explicitly scoped out of Phase 71 (see `71-CONTEXT.md` Deferred Ideas). | gsd-security-auditor | 2026-07-10 |

_Accepted risks do not resurface in future audit runs._

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|----------------|--------|------|--------|
| 2026-07-10 | 12 | 12 | 0 | gsd-security-auditor (ASVS L2, block_on: high) — static verification: source-read against all 12 threat IDs across 9 `71-*-PLAN.md` `<threat_model>` registers; automated evidence (orchestrator-reported): `pnpm typecheck` green, apps/api Jest 894/894 green, `cargo check --all-targets` green, sdk-e2e Test 21 (D-06) proven live with one 200 + one 409 |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-07-10
