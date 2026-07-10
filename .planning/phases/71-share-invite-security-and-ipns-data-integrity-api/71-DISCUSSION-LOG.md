# Phase 71: Share-Invite Security and IPNS Data-Integrity (API) - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-07
**Phase:** 71-share-invite-security-and-ipns-data-integrity-api
**Areas discussed:** Root ownership source, rootNodeId validation, SC#3 root-uniqueness index, CID equivocation (D-09), Re-claim grant semantics (SC#2)

---

## Root ownership source (SC#1) — user requested flows laid out before deciding

Traced the actual data flows: two stores record user→root (`vaults` FK-backed unique-per-owner, and `ipns_records.is_root` with `user_id` a documented "denormalized creator marker"); `createInvite` consults neither and copies `rootIpnsName`/`rootNodeId` verbatim from the untrusted DTO.

| Option | Description | Selected |
|--------|-------------|----------|
| vaults (Flow C) | Check `vaults WHERE owner_id AND root_ipns_name` — FK-backed, unique per user, purpose-built | ✓ |
| ipns_records.is_root (Flow A) | Check `ipns_records WHERE user_id AND ipns_name AND is_root` — trusts the non-authoritative creator marker | |
| Make user_id authoritative (Flow B) | Elevate `ipns_records.user_id`; fights the signature-authority design, redundant with vault | |

**User's choice:** vaults (Flow C)
**Notes:** Chosen once the FK-backed `vaults` entity and the `ipns_records` denormalization comment ("authority is proven by the record's signature, not by row ownership") were surfaced. Ownership ceiling acknowledged: no key-possession proof exists; this raises ownership to "authenticated registrant."

---

## rootNodeId validation (SC#1)

| Option | Description | Selected |
|--------|-------------|----------|
| Validate ipnsName only | Verify `rootIpnsName` via vaults; accept `rootNodeId` as client-asserted; note the gap | ✓ |
| Persist root_node_id on vaults | Add column + `/vault/init` write to validate the full pair | |

**User's choice:** Validate ipnsName only
**Notes:** No server store records a root's nodeId today. Full-pair validation deferred (would add a migration + vault-init write-path change).

---

## SC#3 root-uniqueness index

| Option | Description | Selected |
|--------|-------------|----------|
| Add it (defense-in-depth) | Add `ipns_records(user_id) WHERE is_root` partial unique index | |
| Skip — vault already enforces it | `vaults.owner_id` uniqueness already enforces one-root-per-user | ✓ |

**User's choice:** Skip — vault already enforces it
**Notes:** SC#3 flagged for revision — its `claim_count` CHECK-constraint half still applies; the root-uniqueness-index half is dropped as already-covered.

---

## CID equivocation (SC#4 / D-09)

Provisionally leaned Hard-guard, then paused to resolve the load-bearing unknown (the TEE re-sign contract). Traced Phase 67's lease-renewer: it re-signs value+seq parsed from the existing record, has no `metadataCid` input, and uses a separate EOL-only write path — so same-seq + different-CID is never legitimately produced.

| Option | Description | Selected |
|--------|-------------|----------|
| Hard-guard (reject 400) | Reject same-seq when incoming CID ≠ stored latestCid; same-CID retries still pass | ✓ |
| Accept + document (ADR) | Keep overwrite; record rationale | |
| Log + overwrite | Keep overwrite, warn on same-seq CID change | |

**User's choice:** Hard-guard (400) — confirmed after TEE contract proven
**Notes:** Guard must reject only on CID mismatch (idempotent same-CID retries pass). Stale "Pitfall 4" test + comment must be rewritten — they encode a TEE behavior Phase 67 made impossible.

---

## Re-claim grant semantics (SC#2)

| Option | Description | Selected |
|--------|-------------|----------|
| Upgrade-merge (widen only) | Apply later grant only if it widens (read→write); never downgrade | ✓ |
| Reject on conflict (409) | Reject claim if a share already exists; change requires revoke-then-reinvite | |

**User's choice:** Upgrade-merge (widen only)
**Notes:** Must resolve the existing-share detection and grant-merge relative to the atomic claim UPDATE (`:141`) so a legitimate widen consumes the invite and a redundant re-claim doesn't silently drop the grant. Preserve write-authority invariant T-66-E1.

## Claude's Discretion

The four mechanical todos (claim_count CHECK constraint, first-publish 409, bulk-revoke direct DELETE, restore unit coverage) carried no gray areas — approach is fully specified in CONTEXT.md (D-04, D-06, D-08, D-09).

## Deferred Ideas

- Cryptographic key-possession proof of root ownership (signature challenge) — own phase.
- Persisting `root_node_id` on `vaults` for full pair validation — deferred (D-02 gap).

---

## D-01 AMENDMENT (2026-07-09, at plan time) — root-ownership source reversed to `ipns_records`

The planner halted at `## PLANNING INCONCLUSIVE` on D-01. Grepping the live invite/share
call sites falsified the load-bearing assumption behind the original vaults-based decision.

**Falsified assumption:** `dto.rootIpnsName` is the caller's *vault root*. Verified false —
sharing is **children-only** (context-menu action on a listing item; `dto.rootIpnsName =
params.item.ipnsName` at `invite.service.ts:172` / `ShareDialog.tsx:216`, always a child node).
`vaults` holds only the one top-level vault root per user, so `vaults WHERE root_ipns_name =
dto.rootIpnsName` never matches a real share — the literal check 403s all sharing, and a
"conflict-only" variant is a no-op protecting nothing. `vaults` is structurally incapable of
verifying a child share.

**Consequence:** the only server-side child-ownership signal is `ipns_records.user_id` (the
creator marker set at first publish) — the former "Flow A," originally rejected only because
`vaults` was (wrongly) believed to cover it.

| Option | Description | Selected |
|--------|-------------|----------|
| Check `ipns_records.user_id` | `SELECT 1 FROM ipns_records WHERE ipns_name=:dto.rootIpnsName AND user_id=:caller`; reject 403 on miss; applied to createInvite + createShare | ✓ |
| Defer D-01 to the crypto key-possession phase | Ship D-02…D-09; leave SC#1 open | |
| Keep literal vaults whitelist | Regresses shipped subfolder/file sharing | ✗ (dead) |

**User's choice:** Check `ipns_records.user_id` (widen SC#1's server-side ownership to
"authenticated node registrant"). Confirmed after tracing the descriptor-ref crypto boundary
(`readDescriptorRef`/`writeDescriptorRef`/`encryptedKey` wrap keys only the sharer holds → a
forged share is cryptographically inert), so the DB check is explicitly defense-in-depth.
Residual weakness (signature, not row-ownership, is true authority) documented like the D-02
nodeId gap. Supersedes the PATTERNS.md `Vault`-forFeature wiring note (dependency is now the
`ipns_records` repo, not `Vault`).
