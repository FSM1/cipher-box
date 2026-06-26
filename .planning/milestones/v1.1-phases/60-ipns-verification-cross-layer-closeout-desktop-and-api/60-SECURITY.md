---
phase: 60
slug: ipns-verification-cross-layer-closeout-desktop-and-api
status: verified
threats_open: 0
asvs_level: standard
created: 2026-06-24
---

# Phase 60 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
| -------- | ----------- | ------------- |
| API/DHT → Rust client | Resolved IPNS response (cid, seq, signatureV2, data, pubKey) from untrusted external source into verified resolver | Signed IPNS record fields |
| crate boundary (fuse/sdk/desktop → api-client) | Consumers depend on the single chokepoint; a weakened chokepoint weakens every consumer | VerifiedResolve struct |
| producer → API publish gate | Client-supplied IPNS record crosses the publish gate; embedded-0 first publish is a wedge vector | Signed IPNS record bytes |
| API/DHT → TS client | Resolved IPNS response crosses into resolveIpnsRecord; untrusted until signature + binding + expiry verified | IPNS resolve response fields |
| DB cache → resolve response | A null-signed or inconsistent DB row served as a cid-only 200 would hand the client an unverifiable CID | FolderIpns DB row |
| client publish → verify anchor | The cache decides whether to skip verification; an incorrect predicate would skip verifying an untrusted record | ipnsVerifyCache key/TTL |
| DHT/someguy resolve → client | DHT records are externally sourced; the cache must NEVER mark them authoritative | DHT-sourced record bytes |
| vector fixture → Rust + TS verifiers | The shared vector is the cross-language parity contract; a stale classification would let one layer drift from strict | verify.json classifications |
| deploy ordering | A wipe-before-deploy ordering would leave embedded-0 records alive under strict verify | Staging DB state |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
| --------- | -------- | --------- | ----------- | ---------- | ------ |
| T-60-01 | Tampering | bind_verified CID binding | mitigate | `embedded_value == /ipfs/{resp.cid}` strict check; `VerifyError::Invalid` on mismatch | closed |
| T-60-02 | Spoofing | verify_ipns_resolve_signature absent-fields path | mitigate | `Ok(None)` legacy branch removed; all-absent fields return `Ok(Some(false))` → `Invalid` | closed |
| T-60-03 | Tampering | bind_verified sequence binding | mitigate | Strict `embedded_seq == resp_seq`; skew disjunct removed; seq-mismatch test asserts Invalid | closed |
| T-60-04 | Tampering | expired-record replay on resolve | mitigate | EOL/expiry in `bind_verified` with 5-min skew buffer; absent Validity is fail-closed | closed |
| T-60-05 | Elevation | wrapper relocation weakening the chokepoint | mitigate | `crates/fuse/src/verify.rs` deleted; single chokepoint in api-client; no behavior softened | closed |
| T-60-06 | DoS | missed producer leaving embedded-0 record | mitigate | All 9 first-publish sites use sequence 1; no `0`/`0n` first-publish literal remains | closed |
| T-60-07 | DoS | embedded-0 wedge poisoning first publish | mitigate | Unified producers + API gate rejects embedded-0 (`embeddedSeq !== 1n` at ipns.service.ts:298) | closed |
| T-60-08 | Spoofing | TS resolve legacy else (missing fields) | mitigate | Legacy `else` deleted; absent fields throw; no `signatureVerified:false` soft-return | closed |
| T-60-09 | Tampering | TS resolve sequence skew | mitigate | Strict `embeddedSeqBigInt === responseSeqBigInt`; skew disjunct removed at ipns/index.ts:279 | closed |
| T-60-10 | Tampering | expired-record replay (TS resolve) | mitigate | CBOR Validity parsed; absent Validity throws; 5-min skew buffer at ipns/index.ts:293-304 | closed |
| T-60-11 | Spoofing | consumer treating soft-return as success | mitigate | All thrown errors propagate as failures; blast-radius audit confirmed consumers do not swallow | closed |
| T-60-12 | Tampering | crates/sdk raw resolve_ipns (registry.rs, sync.rs) | mitigate | Both files route through `cipherbox_api_client::ipns::resolve_ipns_verified` | closed |
| T-60-13 | Tampering | desktop Tauri raw resolve_ipns (6 sites) | mitigate | All 6 desktop sites in prepopulate.rs and vault.rs use `resolve_ipns_verified` | closed |
| T-60-14 | Spoofing | FUSE Legacy warn-and-proceed arms | mitigate | All 9 fuse callers handle only `VerifyError::Invalid` and `VerifyError::Api`; no Legacy arm | closed |
| T-60-15 | Elevation | verify.rs left as stale parallel implementation | mitigate | `crates/fuse/src/verify.rs` absent from filesystem; single chokepoint in api-client confirmed | closed |
| T-60-16 | DoS | first-publish embedded-0 wedge | mitigate | API gate: `embeddedSeq !== 1n` throws BadRequestException (ipns.service.ts:298-300) | closed |
| T-60-17 | Spoofing | null-signed DB row served cid-only | mitigate | `parseCachedRecord` returns `null` when `signedRecord` is null (ipns-record.codec.ts:64-66) | closed |
| T-60-18 | Tampering | embedded≠DB sequence silently overridden | mitigate | CID mismatch between signedRecord and latestCid → `null` (discard, not override) at codec.ts:73-78 | closed |
| T-60-19 | Tampering | legacy resolve enrich masking missing sig fields | mitigate | `withCachedPublicKey` enrich removed; `parseCachedRecord` supplies `pubKey` from validated `publicKey` column; `resolveRecord` prefers DB on equal-or-higher sequence (ipns.service.ts:523) | closed |
| T-60-20 | Tampering | cache short-circuit skipping verify of untrusted record | mitigate | Cache key is full record bytes; populated ONLY after successful `verifyIpnsRecordSignature` in publishRecord; resolve path never populates it (ipns-verify-cache.ts + ipns.service.ts:96-104) | closed |
| T-60-21 | Spoofing | CID-collision cache poisoning | mitigate | Full-triple key includes signatureV2 bytes; a forged record with different signature is a cache miss → full verify | closed |
| T-60-22 | Elevation | TEE skipSigVerify bypass | accept→avoid | TEE republish path (republish.service.ts, republish.processor.ts) does not call `verifyIpnsRecordSignature`; no `skipSigVerify` field or bypass added; structural test guards absence | closed |
| T-60-23 | Tampering | stale vector masking a fail-open layer | mitigate | `legacy-absent` and `first-publish-skew` both `"expected_result": "invalid"` in verify.json; Rust classifier strict (None → "invalid", strict seq equality) | closed |
| T-60-24 | Repudiation | hand-edited vector drifting from generator | mitigate | Vector generated via `npx tsx scripts/gen-ipns-verify-vectors.ts`; idempotence verified; generator source classifies both edge cases as invalid | closed |
| T-60-SC | Tampering | npm/cargo supply chain | mitigate | New Cargo.toml additions (`ciborium`, `cipherbox-core`) are workspace-level pre-existing deps (ciborium@0.2 at Cargo.toml:30; cipherbox-core is a path dep); no new third-party packages | closed |
| T-60-25 | DoS | embedded-0 records alive when strict verify goes live | mitigate | Ordering documented: deploy strict code → wipe → smoke; checkpoint enforced per 60-VALIDATION.md HARD-11 and 60-08 PLAN; staging cutover operationally pending | closed |
| T-60-26 | DoS | local dev DBs with embedded-0 records fail-closed | mitigate | Local-dev-DB-wipe guidance documented in docs/DEVELOPMENT.md (Phase 60 paragraph with dropdb/createdb/pnpm instructions); confirmed at VERIFICATION.md item 16 | closed |
| T-60-27 | Availability | folders fail to resolve post-wipe | mitigate | Smoke-test checkpoint documented in 60-VALIDATION.md HARD-11 and 60-VERIFICATION.md item 17; operational execution pending staging deployment | closed |

_Status: open · closed_
_Disposition: mitigate (implementation required) · accept (documented risk) · accept→avoid (risk accepted via avoidance; no bypass added)_

---

## Accepted Risks Log

No accepted risks. T-60-22 is `accept→avoid`: the risk was accepted by architectural avoidance — the TEE republish path never calls `verifyIpnsRecordSignature` and no `skipSigVerify` bypass was introduced. No residual risk remains.

---

## Operational Checkpoint

T-60-25, T-60-26, T-60-27 are **mitigation-documented, operationally pending**. The code half is delivered and all code gates are green. The staging DB wipe + redeploy + smoke-test (Plan 08 Task 2) is a human-action checkpoint requiring staging VPS access and a live Web3Auth login. This is not a code gap; it is an explicit deploy-ordering invariant (D-12 lockstep) that cannot be automated. Phase must not merge to main until the staging smoke-test is complete.

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
| ---------- | ------------- | ------ | ---- | ------ |
| 2026-06-24 | 27 | 27 | 0 | gsd-security-auditor (claude-sonnet-4-6) |

---

## Unregistered Flags

None. All threat flags reported in SUMMARY files for plans 02, 03, and 06 map to existing threat IDs within the threat register. No new attack surface was detected during implementation.

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / accept→avoid)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter
- [ ] Staging smoke-test (T-60-25/27 operational gate) — pending human execution

**Approval:** verified 2026-06-24 (code gates); staging smoke-test pending operator execution
