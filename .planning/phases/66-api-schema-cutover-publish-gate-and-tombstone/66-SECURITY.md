---
phase: 66
slug: api-schema-cutover-publish-gate-and-tombstone
status: verified
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (high)
threats_open: 0
asvs_level: 1
created: 2026-06-30
---

# Phase 66 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.
> Audited by gsd-security-auditor (verify-mitigations mode, register authored at
> plan time). Initial pass: 16/17 closed, **T-66-E1 OPEN (high)**. T-66-E1 was
> remediated during the ship review (commit on this branch) → **17/17 closed,
> threats_open: 0 → SECURED**.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| Client → API publish | Authenticated client publishes a signed IPNS record | Ed25519-signed IPNS record, sequence, generation, ECIES-wrapped IPNS key |
| Client → API resolve | Any client resolves an IPNS name | IPNS name (public), DB-cached or network record |
| Claimer → API invite claim | Recipient claims a share invite | Re-wrapped ECIES descriptor refs, invite token |
| API → Postgres | Canonical record/grant persistence | Signed records, descriptor refs, TEE-wrapped keys |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-66-EP1 | Elevation of Privilege | `public_key` null for shared rows | high | mitigate | Column dropped; `publicKeyFromIpnsName(ipnsName)` sole recovery — `ipns-record.codec.ts:114`, `ipns.service.ts:575` | closed |
| T-66-T1 | Tampering | concurrent publishes at same seq | high | mitigate | Atomic CAS `UPDATE … WHERE sequence_number = :expected`; `affected === 0 ⇒ 409` — `ipns.service.ts:364-393` | closed |
| T-66-T2 | Tampering | replay of old lower-seq record | high | mitigate | Anti-rollback embedded-seq parse + CAS gate — `ipns.service.ts:255-262,287-313,370` | closed |
| T-66-T3 | Tampering | generation regression | high | mitigate | `generation <= CAST(:incoming AS bigint)` in CAS WHERE — `ipns.service.ts:370` | closed |
| T-66-T4 | Tampering | tombstoned-name re-publish/renewal | high | mitigate | `tombstoned_at IS NULL` in CAS WHERE; 410 split — `ipns.service.ts:370,386-387` | closed |
| T-66-I1 | Information Disclosure | null-signedRecord shared row serving ungated CID | high | mitigate | seqFloor case-split; `networkSeq >= floorSeq` else fail closed — `ipns-record.codec.ts:89-103`, `ipns.service.ts:629-644` | closed |
| T-66-A1 | Elevation of Privilege | non-owner tombstoning | medium | mitigate | `tombstoneRecord` WHERE `user_id = :userId` — `ipns.service.ts:521` | closed |
| T-66-I2 | Information Disclosure | stale ECIES in revoked rows | medium | mitigate | revoke = hard DELETE (`shareRepo.remove`); no `revoked_at` — `shares.service.ts:140` | closed |
| T-66-I3 | Information Disclosure | server plaintext item names | low | mitigate | `itemNameEncrypted` (bytea) only; plaintext columns dropped | closed |
| T-66-T5 | Tampering | duplicate grant rows | low | mitigate | `@Unique(['sharerId','recipientId','rootNodeId'])` — `share.entity.ts:16` | closed |
| T-66-S1 | Spoofing | claimer minting unauthorized grant | medium | mitigate | Root identity copied from invite; self-claim rejected — `share-invite.service.ts:134,186-189` | closed |
| T-66-E1 | Elevation of Privilege | read-only invite yielding write grant | high | mitigate | **(Remediated at ship)** write authority presence-derived from `invite.writeDescriptorRef !== null`, not claimer `dto.writeDescriptorRef` — `share-invite.service.ts:188-192` | closed |
| T-66-D2 | Tampering | recreated table drifts from entities | high | mitigate | Migration column set matches reshaped entities (steps 2/3/5) | closed |
| T-66-T6 | Tampering | stale generated client masks contract change | medium | mitigate | `scripts/check-api-client.sh` pre-commit hook | closed |
| T-66-SC | Tampering | npm/pip/cargo installs | high | accept | No package installs this phase | closed |
| T-66-D1 | Denial of Service | run against DB with real data | low | accept | Greenfield only; staging wiped on deploy; `down()` throws | closed |
| T-66-T7 | Tampering | stub ships broken share flow | low | accept | Intentional throw-stubs; app non-runnable mid-milestone; Phase 68 wires real path | closed |

*Status: open · closed · open — below high threshold (non-blocking)*
*Severity: critical > high > medium > low — only open threats at or above high count toward threats_open*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-66-1 | T-66-SC | No npm/pip/cargo installs in this phase; supply-chain surface unchanged | Phase 66 plan | 2026-06-30 |
| AR-66-2 | T-66-D1 | Greenfield cutover; staging wiped on deploy, no prod data; reversibility deliberately waived (`down()` throws) | Phase 66 plan (D-01) | 2026-06-30 |
| AR-66-3 | T-66-T7 | Intentional throw-stubs in web share consumers; app non-runnable mid-milestone; Phase 68 wires the real path before any web ship | Phase 66 plan (66-08) | 2026-06-30 |

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-06-30 | 17 | 16 | 1 (T-66-E1, high) | gsd-security-auditor |
| 2026-06-30 | 17 | 17 | 0 | ship-phase (T-66-E1 remediated) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-06-30
