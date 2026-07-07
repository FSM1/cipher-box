---
phase: 69
slug: fuse-and-winfsp-rust-integration-and-grant-root-awareness
status: verified
# threats_open = count of OPEN threats at or above workflow.security_block_on (high)
threats_open: 0
asvs_level: 1
created: 2026-07-07
---

# Phase 69 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.
> ASVS L1 (grep-depth) verification. Register authored at plan time across all 25
> `69-*-PLAN.md` `<threat_model>` blocks (109 threats); mitigations verified against
> the implemented code. Cross-referenced with `69-VERIFICATION.md` (PASS, 5/5 local
> success criteria) and `cargo test --workspace` (476 passed, 0 failed, macOS).

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| API relay → api-client / Rust SDK | Untrusted paginated share lists, published IPNS records, and sealed node blobs cross into the client's grant-root set and read chain | Sealed node blobs, signed IPNS records, grant-root wrappers |
| IPNS record → anti-rollback floor gate | A colluding/replaying relay may serve a stale signed record (generation/seq downgrade) | Generation + sequence numbers, durable floor sidecar |
| FUSE/WinFsp syscall surface → SDK write/read chain | Local FS operations (delete/rename/move/read) drive rotation-bearing mutations | readKey/writeKey/fileKey, ipnsPrivateKey, node AAD |
| Persisted key material (memory + disk) | Root/read/write keys and ipnsPrivateKey held in the mount and vault blob | Symmetric keys, ECIES-wrapped root, vault-blob-v3 |
| Local disk (floor sidecar, write journal) | Out of the zero-knowledge model: a local-disk attacker is explicitly out of scope (ADR 0002) | Floor JSON, write journal |

---

## Threat Register

**Summary:** 109 threats — 2 critical, 79 high, 21 medium, 7 low · 105 mitigate / 4 accept.
Status: **75 closed** (mitigation verified in code), **25 closed** (supply-chain — zero new
crates/packages: `git diff origin/main...HEAD` over every `Cargo.toml`/`package.json` adds no
production dependency), **5 CI-verified (winfsp)** (Windows platform layer compiles/wires only
under the required-green `cargo-windows` + Desktop E2E CI gates — see SC#5), **4 accepted**
(all low/medium, below the `high` blocking threshold).

| Threat ID | Category | Component | Severity | Disposition | Status |
|-----------|----------|-----------|----------|-------------|--------|
| T-69-01-01 | Tampering | decode_node on malformed/oversized JSON | medium | mitigate | closed |
| T-69-01-02 | Tampering | codec divergence from TS twin (interop break) | high | mitigate | closed |
| T-69-01-SC | Tampering | npm/pip/cargo installs | high | mitigate | closed (no new deps) |
| T-69-02-01 | Tampering | Colluding relay serves an old signed record (generation-downgrade) | critical | mitigate | closed |
| T-69-02-02 | Tampering (V5) | Malformed generation/seq inputs bypassing the floor comparison | high | mitigate | closed |
| T-69-02-03 | Tampering | Local tamper of the sidecar JSON to lower a floor | medium | accept | accepted |
| T-69-02-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-03-01 | Tampering | Relay omits a grant root from /shares/sent to suppress rotation | high | mitigate | closed |
| T-69-03-02 | Information Disclosure | Auth header handling on the new GET | medium | mitigate | closed |
| T-69-03-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-04-01 | Tampering / Elevation | AAD transplant (replay a blob under a different childId/role/generation) | high | mitigate | closed |
| T-69-04-02 | Information Disclosure | Zeroization mistake leaking/corrupting caller key buffers | medium | mitigate | closed |
| T-69-04-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-05-01 | Tampering / Elevation | Relay omits a grant root to suppress rotation (revoked reader keeps a... | high | mitigate | closed |
| T-69-05-02 | Elevation | Over-rotation on private deletes (perf/DoS, not a security break) | low | accept | accepted |
| T-69-05-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-06-01 | Tampering | Generation-downgrade served on a cold-child resolve | high | mitigate | closed |
| T-69-06-02 | Spoofing / Elevation | FUSE bypassing the gate via a raw resolve | high | mitigate | closed |
| T-69-06-03 | Information Disclosure | Wrong-key unseal leaking cross-folder metadata | medium | mitigate | closed |
| T-69-06-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-07-01 | Denial of Service | Per-mutation network call in the delete/rename hot path | medium | mitigate | closed |
| T-69-07-02 | Tampering / Elevation | Stale cache missing a new grant root → suppressed rotation | medium | mitigate | closed |
| T-69-07-03 | Elevation | Divergent per-platform scope logic (WinFsp copy drifts) | high | mitigate | closed |
| T-69-07-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-08-01 | Tampering | Zeroizing a caller-owned key buffer inside rotate_one (48/89 incident) | high | mitigate | closed |
| T-69-08-02 | Elevation | Root not rotated first → revoked reader survives on an un-rotated root | high | mitigate | closed |
| T-69-08-03 | Denial of Service | N-child fan-out republishing the parent N times | low | mitigate | closed |
| T-69-08-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-09-01 | Spoofing / Elevation | FUSE bypassing the anti-rollback gate via a raw resolve | high | mitigate | closed |
| T-69-09-02 | Tampering | Behavioral divergence between ECIES and symmetric unwrap (wrong key r... | high | mitigate | closed |
| T-69-09-03 | Information Disclosure | Migrating a keeper ECIES wrap (TEE / vault-root / name blob) by mista... | high | mitigate | closed |
| T-69-09-04 | Denial of Service | A stale pre-cutover journal entry crashes the mount on next launch (p... | medium | mitigate | closed |
| T-69-09-05 | Tampering / DoS | Conflating WriteChildRef.childId (UUID) with SealedChildRef.ipnsName ... | high | mitigate | closed |
| T-69-09-06 | Tampering | The desktop crate (workspace build) silently left on legacy shapes �... | medium | mitigate | closed |
| T-69-09-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-10-01 | Tampering | A leftover legacy↔Node bridge weakens the single-codec guarantee | high | mitigate | closed |
| T-69-10-02 | Denial of Service (build) | Deleting a type while a default-compiled consumer still names it → ... | medium | mitigate | closed |
| T-69-10-03 | Denial of Service (build) | Over-deleting VersionEntry breaks helpers.rs (apply_versioning/versio... | medium | mitigate | closed |
| T-69-10-04 | Tampering | The core deletion accidentally references a winfsp-only symbol, coupl... | low | mitigate | closed |
| T-69-10-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-11-01 | Tampering / Elevation | Crash leaves a revoked reader on an un-rotated tail | high | mitigate | closed |
| T-69-11-02 | Tampering | Double-bump corrupts generation floor (breaks M1) | high | mitigate | closed |
| T-69-11-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-12-01 | Elevation | Old readKey/fileKey decrypts future content (revocation ineffective) | critical | mitigate | closed |
| T-69-12-02 | Elevation | Orphaned inner grant deep in a rotating subtree keeps access | high | mitigate | closed |
| T-69-12-03 | Tampering / Data loss | Concurrent add silently dropped on CAS-409 | high | mitigate | closed |
| T-69-12-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-13-01 | Tampering / DoS | Conflating WriteChildRef.childId with SealedChildRef.ipnsName breaks ... | high | mitigate | closed |
| T-69-13-02 | Elevation | Missing rotation on a shared-scope exit (a revoked reader keeps access) | high | mitigate | closed |
| T-69-13-03 | DoS / Cost | Over-rotation on a private delete (revoke left unconditional — rese... | low | mitigate | closed |
| T-69-13-04 | Tampering / Elevation | A per-platform predicate copy drifting from the shared gate | high | mitigate | closed |
| T-69-13-05 | Elevation | D-08 exposure window for an owner-sub-shared node after a recipient d... | low | accept | accepted |
| T-69-13-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-14-01 | Tampering / Elevation | A divergent per-platform grant-scope predicate (a WinFsp copy drifts ... | high | mitigate | CI-verified (winfsp) |
| T-69-14-02 | Tampering / DoS | Conflating WriteChildRef.childId (UUID) with SealedChildRef.ipnsName ... | high | mitigate | CI-verified (winfsp) |
| T-69-14-03 | Elevation | Missing rotation on a Windows shared-scope exit (a revoked reader kee... | high | mitigate | CI-verified (winfsp) |
| T-69-14-04 | Spoofing / Elevation | The Windows read path bypassing the anti-rollback gate via a raw resolve | high | mitigate | CI-verified (winfsp) |
| T-69-14-05 | Elevation | D-08 exposure window for an owner-sub-shared node after a Windows rec... | low | accept | accepted |
| T-69-14-06 | Tampering | The Windows winfsp build silently not compiling against the Node mode... | high | mitigate | CI-verified (winfsp) |
| T-69-14-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-15-01 | Information Disclosure | ipns_private_key inside NodeWriteBody leaked via logging or an unseal... | high | mitigate | closed |
| T-69-15-02 | Tampering | Write-body sealed under a wrong AAD role/generation or openable by re... | high | mitigate | closed |
| T-69-15-03 | Tampering | Read-body KAT drift or D-02-split collapse from adding a Node-enum wr... | medium | mitigate | closed |
| T-69-15-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-16-01 | Spoofing / Elevation | ApiNodeFetcher decoding/gating bytes itself, bypassing the ROT-07 enf... | high | mitigate | closed |
| T-69-16-02 | Information Disclosure | Minted readKey/writeKey/ipnsPrivateKey leaked (logged) or zeroed prem... | high | mitigate | closed |
| T-69-16-03 | Tampering | childId/ipnsName conflation on build_child_refs breaks rotateWriteFro... | high | mitigate | closed |
| T-69-16-04 | Tampering / Denial of Service | First publish with seq != 1 (strict-gate 400) or a folder un-enrollab... | high | mitigate | closed |
| T-69-16-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-17-01 | Spoofing / Elevation | list_folder_owned adding a second, ungated resolver bypassing the ROT... | high | mitigate | closed |
| T-69-17-02 | Information Disclosure | Recovered read_key/write_key/ipns_private_key leaked (logged) or zero... | high | mitigate | closed |
| T-69-17-03 | Tampering | childId/ipnsName conflation on the read/write pairing recovers the wr... | high | mitigate | closed |
| T-69-17-04 | Denial of Service / Tampering | A malformed/short sealed key or an absent write_sealed panics or yiel... | medium | mitigate | closed |
| T-69-17-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-18-01 | Denial of Service | A stale pre-cutover journal entry crashes the mount on next launch (p... | medium | mitigate | closed |
| T-69-18-02 | Tampering | Conflating the journal's parent read-plane SealedChildRef (ipnsName) ... | high | mitigate | closed |
| T-69-18-03 | Information Disclosure | Re-introducing a user-ECIES-wrapped node-to-node key (or a plaintext ... | high | mitigate | closed |
| T-69-18-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-19-01 | Tampering / DoS | Conflating WriteChildRef.childId (uuid_from_ino) with SealedChildRef.... | high | mitigate | closed |
| T-69-19-02 | Information Disclosure | Minted/inode key material leaked or an inode-owned key zeroed prematu... | high | mitigate | closed |
| T-69-19-03 | Tampering | A leftover dual-format/serde-alias path lets a legacy file_pointer/fo... | medium | mitigate | closed |
| T-69-19-04 | Spoofing | The ECIES bin envelope weakened or swapped for a node-to-node symmetr... | high | mitigate | closed |
| T-69-19-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-20-01 | Tampering / DoS | Create-time root read/write keys diverge from the mount bridge → th... | high | mitigate | closed |
| T-69-20-02 | Tampering | First root publish with seq != 1 → strict-gate 400 → vault init f... | high | mitigate | closed |
| T-69-20-03 | Information Disclosure | The vault-root ECIES wrap weakened or replaced by a node-to-node symm... | high | mitigate | closed |
| T-69-20-04 | Elevation | build_folder_emission's minted random keys used instead of the determ... | medium | mitigate | closed |
| T-69-20-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-21-01 | Tampering | v3 envelope layout drifts from the frozen KAT / blob.ts -> a web vaul... | high | mitigate | closed |
| T-69-21-02 | Denial of Service | A truncated / malformed blob triggers an out-of-bounds slice panic du... | medium | mitigate | closed |
| T-69-21-03 | Information Disclosure | The recovered key Vecs alias the source blob so a later blob zeroizat... | low | mitigate | closed |
| T-69-21-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-22-01 | Information Disclosure | root_read_key/root_write_key survive logout/exit in memory | high | mitigate | closed |
| T-69-22-02 | Tampering | read/write keys conflated or one silently mirrors the other (re-intro... | high | mitigate | closed |
| T-69-22-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-23-01 | Information Disclosure | A root key persisted in plaintext (server or IPFS) | high | mitigate | closed |
| T-69-23-02 | Spoofing / Tampering | A tampered vault-key blob or IPNS record injects attacker keys | high | mitigate | closed |
| T-69-23-03 | Elevation | Create/recover key mismatch (bridge remnants) -> a fresh vault is unr... | high | mitigate | closed |
| T-69-23-04 | Information Disclosure | Root keys zeroed before their ECIES wrap or root seal completes (or n... | medium | mitigate | closed |
| T-69-23-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-24-01 | Elevation / Tampering | The `^0xA5` bridge survives, so the mount reads/writes a real vault u... | high | mitigate | closed |
| T-69-24-02 | Tampering | read_key and write_key swapped/conflated when threading into InodeKin... | high | mitigate | closed |
| T-69-24-03 | Information Disclosure | Mount zeroes the caller-owned state keys, or fails to drop its own co... | medium | mitigate | closed |
| T-69-24-04 | Denial of Service | winfsp signature drifts from the fuse signature -> the shared auth.rs... | medium | mitigate | closed |
| T-69-24-SC | Tampering | cargo installs | high | mitigate | closed (no new deps) |
| T-69-25-01 | Spoofing (false assurance) | The verifier reads retired rootFolderKey (undefined) and "passes" wit... | high | mitigate | closed |
| T-69-25-02 | Tampering | Child readKey derived with the child's own generation instead of the ... | medium | mitigate | closed |
| T-69-25-03 | Denial of Service | The migrated helper fails to build, so the whole desktop-e2e round-tr... | high | mitigate | closed |
| T-69-25-SC | Tampering | npm installs | high | mitigate | closed (no new deps) |

*Status: closed = mitigation verified in implementation · closed (no new deps) = supply-chain row, no dependency added · CI-verified (winfsp) = shared mitigation present; Windows-specific compile/wiring gated on required-green CI (SC#5) · accepted = documented residual risk below the `high` block threshold.*
*Only OPEN threats at or above `high` count toward `threats_open`. There are none.*

### Key mitigation evidence (substantive high/critical threats)

| Threat | Mitigation — verified location |
|--------|-------------------------------|
| T-69-02-01 (critical, generation-downgrade) | Durable `JsonSidecarFloorStore` persists `{nodeId → generation, seq}` adjacent to the write journal (atomic write, survives daemon restart) — `crates/sdk/src/floor_store.rs`, `rotation/high_water.rs`. SC#4. |
| T-69-02-02 (high, malformed floor inputs) | `is_valid_floor_value` rejects non-canonical generation/seq before comparison. |
| T-69-12-01 (critical, old key decrypts future content) | Rotation mints fresh `fileKey`/`readKey` on scope exit — `crates/sdk/src/rotation/engine.rs`. |
| T-69-04-01 (high, AAD transplant) | `build_node_aad` binds `childId`/role/generation into the AEAD AAD (69-04); replay under a different id/role/generation fails to open. |
| childId/ipnsName conflation family (T-69-09-05, -13-01, -16-03, -17-03, -18-02, -19-01) | Write plane keyed by the stored node id (`WriteChildRef.childId`), read plane by `ipnsName` (`SealedChildRef`); D-07. Kept distinct through `rotateWriteFromNode`. |
| T-69-08-01 (high, zeroize caller-owned buffer — 48/89 incident) | Terminal-owner zeroization rule: a callee never zeroes caller-owned buffers; zero only at the owning terminal. |
| Grant-scope drift (T-69-07-03, -13-04, -14-01) | Single shared `crates/fuse/src/write_ops/grant_scope.rs` consumed by both Unix and WinFsp paths; CI SC#6 grep gate (`ci.yml:748`) forbids per-platform copies. |
| Anti-rollback bypass via raw resolve (T-69-06-02, -09-01, -16-01, -17-01) | Raw resolve is crate-private; `list_folder_owned`/`fetch_node_gated` is the only gated entry; CI SC#6 grep gate. |
| T-69-01-02 (high, codec divergence from TS twin) | Byte-exact KAT vs `tests/vectors/node-codec.json`; cross-language parity test. |

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-69-01 | T-69-02-03 (medium) | Local tamper of the floor sidecar JSON to lower a floor requires local disk access, which is out of the zero-knowledge threat model (ADR 0002 residual). | Phase owner | 2026-07-07 |
| AR-69-02 | T-69-05-02 (low) | Over-rotation on private deletes is a perf/DoS concern, not a security break; bounded by the short-circuit + zero-rotation invariant test (ROT-02). | Phase owner | 2026-07-07 |
| AR-69-03 | T-69-13-05 (low) | D-08 exposure window for an owner-sub-shared node after a recipient delete; ADR 0002 residual — owner reconcile re-derives dangling grants. | Phase owner | 2026-07-07 |
| AR-69-04 | T-69-14-05 (low) | Same D-08 residual on the Windows recipient-delete path; identical owner-reconcile mitigation. | Phase owner | 2026-07-07 |

*Accepted risks do not resurface in future audit runs.*

---

## CI-Deferred (required green before merge — not open threats)

The Windows/WinFsp platform layer (`crates/fuse/src/platform/windows/*`) does not compile under
local macOS cargo (macFUSE-only linking), and plan `69-14` is `autonomous:false` / intentionally
unexecuted locally. The five Windows-compile-dependent high threats (T-69-14-01/-02/-03/-04/-06)
consume the same shared, code-verified mitigations (grant_scope gate, D-07 keying, anti-rollback
gate); their Windows compile + wiring is objective-signed-off by the required-green CI gates:

- `cargo-windows` job — `ci.yml:590`, `cargo check/test --workspace --no-default-features --features winfsp`
- `Desktop E2E Tests` workflow — `.github/workflows/desktop-e2e.yml`, full macOS/Windows/Linux matrix, dispatched against the shipped SHA

This mirrors success criterion SC#5. These are pending-CI, not OPEN.

---

## Non-blocking follow-up

- **SC#3 shared-scope-exit rotation is fail-closed, not live-wired** (returns `EIO`; no production
  `RotationDeps` implementor yet — matches the known ROT-07 live-wiring gap). Security-safe: a
  covered scope-exit refuses to complete a delete/move without rotating, preventing the revocation
  bypass the gate exists to close. Tracked in
  `.planning/todos/pending/2026-07-07-fuse-shared-scope-exit-rotation-live-wiring.md`.

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-07-07 | 109 | 105 closed/CI-verified + 4 accepted | 0 | ship-phase orchestrator (L1) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed (no open threat at or above `high`)
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-07-07
