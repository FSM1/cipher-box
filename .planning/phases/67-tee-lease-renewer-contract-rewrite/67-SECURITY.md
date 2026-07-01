---
phase: 67
slug: tee-lease-renewer-contract-rewrite
status: verified
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
created: 2026-07-01
---

# Phase 67 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.
> Register authored at plan time (all 8 plans carry a `<threat_model>` block). The
> gsd-security-auditor verified each mitigation exists and is actually enforced in code
> (verify-only mode; no new-threat scan). Verdict: **SECURED, threats_open: 0**.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| relay→TEE | The relay is untrusted; the only signing inputs are the marshaled `signedRecord` + encrypted key, both validated inside the enclave | Marshaled IPNS record, ECIES-wrapped Ed25519 key |
| enclave clock | The TEE's own clock is the epoch authority — never a relay-supplied scalar | `EPOCH_ZERO_TIMESTAMP_MS` (env, TEE-internal) |
| relay→DB | The relay writes/reads the schedule + `ipns_records`; the schedule must not carry authoritative signing inputs | Scheduling metadata only (post-collapse) |
| schedule snapshot→signer | The schedule must not feed authoritative signing inputs; canonical inputs come solely from `ipns_records` | CID, sequence, key, epoch (now sourced from `ipns_records`) |
| client→relay | The encrypted IPNS key is ECIES-wrapped client-side under the TEE public key; the relay only relays it | Wrapped Ed25519 private key |
| enclave key handling | The decrypted Ed25519 key lives only transiently and is zeroed after last use on every path | Plaintext Ed25519 seed (transient, in-enclave) |
| dev host→tee-worker | Local relay reaches the simulator worker over loopback `:3002` | Republish batch payload (dev only) |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-67-01-T | Tampering | schedule snapshot columns | high | mitigate | `1751000000000-ScheduleCollapse.ts` drops `latest_cid`,`sequence_number`; entity carries no signing columns; inputs built from `ipns_records` (`republish.service.ts` teeEntries) | closed |
| T-67-01-I | Info Disclosure | `encrypted_ipns_key` residue on schedule | medium | mitigate | `ScheduleCollapse.ts` drops `encrypted_ipns_key`; entity carries no key column | closed |
| T-67-02-E | Elevation | relay-supplied `currentEpoch` | high | mitigate | `decryptWithFallback(encryptedIpnsKey, keyEpoch)` derives `internalCurrentEpoch=getInternalCurrentEpoch()`; no relay epoch param (`tee-keys.ts`) | closed |
| T-67-02-E2 | Elevation | stale epoch-N-2 key survival | high | mitigate | `key-manager.ts` throws `ReEnrollRequiredError` before the trial-1 unwrap — key never decrypted | closed |
| T-67-02-I | Info Disclosure | key bytes in error/log | medium | mitigate | `ReEnrollRequiredError` message names epoch integers only; no key material | closed |
| T-67-03-T | Tampering | sequence increment / CID repoint | critical | mitigate | `renewIpnsRecord(ed25519PrivateKey, marshaledExistingRecord)` — **no cid/seq args**; value+sequence read from `parseIpnsRecord(...)` only; structurally cannot repoint or increment | closed |
| T-67-03-S | Spoofing | `parsed.pubKey` reliance | medium | mitigate | `renewIpnsRecord` reads only `parsed.value`/`parsed.sequence`; never `parsed.pubKey` | closed |
| T-67-04-D | DoS | subfolder IPNS silently expires | medium | mitigate | `registration.ts` fail-closed (throws on missing `currentPublicKey`/non-finite `currentEpoch`); wired to `createAndPublishIpnsRecord` | closed |
| T-67-04-I | Info Disclosure | plaintext IPNS key leak | high | mitigate | `registration.ts` `wrapKey(ipnsPrivateKey, teePublicKeyBytes)` ECIES-wraps under the TEE public key before transmit; server stays zero-knowledge | closed |
| T-67-05-T | Tampering | wrong upstream (mock vs worker) | medium | mitigate | `docker-compose.yml` `127.0.0.1:3002:3001`; `.env.example` `TEE_WORKER_URL=http://localhost:3002` | closed |
| T-67-05-E | Elevation | simulator in production | high | mitigate | `tee-keys.ts` `getKeypair` throws when `TEE_MODE=simulator` + production env | closed |
| T-67-06-T | Tampering | relay arbitrary CID/seq | critical | mitigate | `republish.ts` verifies Ed25519 signature (`verifyIpnsRecordSignature`) **before** decryption; re-signs via `renewIpnsRecord` | closed |
| T-67-06-S | Spoofing | name A signed with key B | high | mitigate | `republish.ts` byte-compares `deriveEd25519PublicKey(decryptedKey)` vs `publicKeyFromIpnsName(ipnsName)`; rejects on mismatch | closed |
| T-67-06-E | Elevation | relay forces wrong re-encrypt epoch | high | mitigate | `republish.ts` epoch-upgrade target = `getInternalCurrentEpoch()`; relay scalars removed | closed |
| T-67-06-I | Info Disclosure | key bytes in error/result | high | mitigate | `republish.ts` zeros the decrypted key on every path (success, binding-fail, error); `key-manager.ts` zeros epoch key in `finally` | closed |
| T-67-06-T2 | Tampering | `parsed.pubKey` trust (undefined for Ed25519) | medium | mitigate | binding derives pubkey from decrypted key + name, never `parsed.pubKey` | closed |
| T-67-07-T | Tampering | stale schedule snapshot as signing input | high | mitigate | `republish.service.ts` teeEntries sourced from `record.*`; only `ipnsName` from schedule | closed |
| T-67-07-T2 | Tampering | seq regress under forward-publish race | high | mitigate | `renewIpnsRecordEol` equality CAS `sequence_number = :expected`; `affected===0` → discard. `LessThanOrEqual` is on `nextRepublishAt` (time), not sequence | closed |
| T-67-07-S | Spoofing | tombstoned name re-signed | high | mitigate | two-layer: pre-batch `tombstonedAt: IsNull()` filter + CAS `tombstoned_at IS NULL` on the write | closed |
| T-67-07-E | Elevation | relay-supplied epoch | high | mitigate | `RepublishEntry` (tee.service.ts / republish.ts) carries no `currentEpoch`/`previousEpoch` | closed |
| T-67-08-T | Tampering | false-positive verify (types pass, DB not migrated) | high | mitigate | `ScheduleCollapse.ts` drops 4 cols; **hardened in this ship pass**: `tee-republish.test.ts` `beforeAll` now asserts the 4 columns are absent via `information_schema.columns` — the drop is re-checked on every run | closed |
| T-67-08-S | Spoofing | tombstoned name re-signed | high | mitigate | `tee-republish.test.ts` Test B asserts the tombstoned name is never re-signed forward | closed |
| T-67-08-D | DoS | flaky cron-timing wait | medium | mitigate | `tee-republish.test.ts` `makeScheduleDue` + single `queue.add('republish-batch')`; no scheduler wait | closed |
| T-67-SC | Supply Chain | npm installs | low | accept | No new-to-repo packages; `bullmq`/`pg` already in `pnpm-lock.yaml` and declared in `tests/sdk-e2e/package.json` | closed |

*Severity: critical > high > medium > low — only open threats at or above `security_block_on` (high) count toward `threats_open`.*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-67-SC | T-67-SC | No new-to-repo packages introduced; `bullmq`/`pg` pre-exist in the lockfile at pinned versions and are declared as sdk-e2e devDeps. Supply-chain surface unchanged. | Phase 67 ship (gsd-security-auditor) | 2026-07-01 |

*Accepted risks do not resurface in future audit runs.*

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-07-01 | 24 | 24 | 0 | gsd-security-auditor (verify-only, ASVS L1, block_on: high) |

**Auditor notes carried forward:**

- All three CRITICAL mitigations (T-67-03-T, T-67-06-T, T-67-06-S) verified as actually
  enforced in code, not merely documented. `renewIpnsRecord` takes no cid/seq argument;
  signature verification precedes decryption; the name↔key binding byte-compares the
  name-derived pubkey and never reads `parsed.pubKey`.
- The `currentEpoch` string still appears in the TEE request path only as comments
  (`republish.ts`) or the internally-derived epoch (`key-manager.ts`) — never a relay
  scalar. The only route accepting a relay `currentEpoch` is `migrate.ts` (the
  config-migration route), which is out of scope for the republish contract.
- T-67-08-T hardening (auditor recommendation) **applied during ship**: the
  `information_schema` column-drop assertion is now embedded in the sdk-e2e suite's
  `beforeAll`, so a future run cannot green against an un-migrated schema.

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-07-01
