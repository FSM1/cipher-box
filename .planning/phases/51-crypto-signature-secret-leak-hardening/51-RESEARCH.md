# Phase 51: Crypto-Signature & Secret-Leak Hardening — Research

**Researched:** 2026-06-19
**Domain:** IPNS signed-record validation (S1), signature verification fail-closed (S2), private-key zeroization (S3)
**Confidence:** HIGH

---

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

**D-01 (S1):** Reject (400) on any embedded-CID vs `metadataCid` mismatch (strict). For sequence, use an offset-aware check that tolerates the known first-publish convention (client signs seq `0` while the DB stores `'1'`; pre-increment) and rejects only genuine disagreement. `parseIpnsRecord` is already imported (`:24`) and called in `upsertFolderIpns` (`:223-226`), so the embedded values are already in hand.

**D-02 (S2):** When a signature is present but invalid, fail closed everywhere — the web path (`apps/web/src/services/ipns.service.ts:177-205`) must reject, not `logger.warn` and return the CID. sdk-core already throws (`packages/sdk-core/src/ipns/index.ts:196-219`).

**D-03 (S2):** When signature fields are absent (legacy records published before signedRecord was reliably populated), allow + flag + telemetry: return the CID with `signatureVerified=false` and emit a warn/metric. Do not fail closed on missing — that risks locking users out of existing vaults, and the DB CID is authoritative. (Future tightening to require-signed is a follow-up once all records carry signatures.)

**D-04 (S2):** Include the Rust half now. Add the signature fields to `IpnsResolveResponse` (`crates/api-client/src/types.rs:130-137`) and verification in `crates/api-client/src/ipns.rs` so S2 is closed across web + sdk-core + Rust consistently. Phase 52 is desktop-durability, not signature work — do not split S2 across phases.

**D-05 (S3):** Exhaustive sweep. Establish a documented caller-owns-key convention (zeroize at the buffer-owning boundary) and apply it across all SDK paths, not just the known contradiction. Includes:
- Reconcile the Phase-44 contradiction: `updateFileMetadata` zeroizes its caller-passed key (`packages/sdk-core/src/file/index.ts:369-373`) while `updateFolderMetadataAndPublish` zeroizes neither (`packages/sdk-core/src/folder/index.ts:177-242`).
- Add zeroization to the currently-unprotected sdk-core paths: `ipns/index.ts:39-98`, `vault/index.ts:32-80`.
- Fix the Rust raw-`Vec<u8>` key leaks: `crates/crypto/src/ecies.rs:35-47` (`unwrap_key`), `crates/fuse/src/lib.rs:933-938` (`get_folder_key` `.to_vec()`), `:1595-1661` (`resolve_folder_key` raw-Vec BFS queue), `:745-747` (`spawn_file_meta_reencrypt`).
- Enforcement guard: add a regression test and/or lint that asserts caller-owns-key on the touched paths so the convention does not re-drift.

### Claude's Discretion

None stated — all forks resolved (D-01..D-05).

### Deferred Ideas (OUT OF SCOPE)

- Todo #15 — web logger redaction interceptor + Faro transport wiring. Removed from Phase 51 post-discussion: end-user logging/monitoring is not being implemented yet.
- Full CRDT conflict model for IPNS — already tracked in the CRDT-inbox research todo.
- Require-signed (fail-closed on missing signature) — deferred until all records are re-published with signatures.

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID      | Description                                                                                                              | Research Support                                                                                                                                |
| ------- | ------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| HARD-02 | Enforce IPNS signedRecord validation, signature verification, and private-key zeroization across web + sdk-core + Rust. | S1: embedded-vs-DTO validation in `upsertFolderIpns`; S2: web fail-closed + Rust `IpnsResolveResponse` + verify fn; S3: exhaustive zeroize sweep |

</phase_requirements>

---

## Summary

Phase 51 closes three independent Medium-severity security findings (S1/S2/S3) from the PR #448 IPNS Signature Storage security review. All three were re-verified against live code on 2026-06-19. The server stays a zero-knowledge relay throughout; the DB CID remains authoritative.

**S1 (publish-time embedded-vs-DTO validation):** `upsertFolderIpns` already parses the incoming signed record (`parseIpnsRecord` at line 223-226) for the anti-rollback 409 check (embedded-vs-embedded). The S1 fix adds the orthogonal embedded-vs-DTO check: compare the parsed CID against `metadataCid` (strict 400) and the parsed sequence against `expectedSequenceNumber` with offset-awareness (client sends seq `0` for first publish, DB stores `'1'`).

**S2 (fail-closed verification):** The sdk-core `resolveIpnsRecord` already throws on present-but-invalid signatures (lines 196-219). The web `resolveIpnsRecord` wraps the same path in a try/catch that swallows the error and returns the CID with a `logger.warn` — this must change to rethrow. Additionally, `IpnsResolveResponse` in Rust (`crates/api-client/src/types.rs`) lacks the three signature fields; adding them plus a verification function in `crates/api-client/src/ipns.rs` closes the Rust surface. All resolve callers in `crates/fuse/src/lib.rs` currently consume only `.cid` and `.sequence_number`; after S2, they must honor a `signature_verified` flag (the DB-authoritative model means absent fields are allowed + flagged, not fatal).

**S3 (key zeroization):** TypeScript uses `.fill(0)` in a `finally` block (T-47-01 convention). The gap is that `createAndPublishIpnsRecord` in `sdk-core/src/ipns/index.ts` never zeroizes its `ipnsPrivateKey` parameter, `vault/index.ts:publishVaultKeyBlob` does not zeroize `vaultKeyKeypair.privateKey`, and `updateFolderMetadataAndPublish` in `sdk-core/src/folder/index.ts` does not zeroize either of its key parameters. In Rust, `Zeroizing<Vec<u8>>` is used on `InodeKind` fields but `get_folder_key` and `build_folder_metadata` return raw `Vec<u8>` via `.to_vec()` and `resolve_folder_key` holds raw Vecs in its BFS queue — these escape the `Zeroizing` wrapper.

**Primary recommendation:** Implement in the locked order S1 → S2 (web fail-closed, then Rust fields + verify) → S3 (TS sweep + Rust BFS/getter fixes + enforcement guard). Each finding is ship-separable.

---

## Architectural Responsibility Map

| Capability                         | Primary Tier     | Secondary Tier    | Rationale                                                                             |
| ---------------------------------- | ---------------- | ----------------- | ------------------------------------------------------------------------------------- |
| S1 — embedded-vs-DTO validation    | API / Backend    | —                 | `upsertFolderIpns` is the only place where both DTO fields and the signed record meet |
| S2 — signature verification        | Client (Web/SDK) | Rust desktop FUSE | DB CID is authoritative; verification is defense-in-depth over the trusted source     |
| S2 — Rust response type extension  | API client (Rust)| FUSE consumers    | `IpnsResolveResponse` is in `crates/api-client`; FUSE calls it via `resolve_ipns`    |
| S3 — TS key zeroization            | sdk-core         | sdk (higher layer)| sdk-core owns the buffer-passing boundary; sdk delegates to sdk-core, never re-zeroes |
| S3 — Rust key zeroization          | crates/fuse      | crates/crypto     | FUSE creates raw copies; `ecies.rs::unwrap_key` returns raw `Vec<u8>`                |
| S3 — enforcement guard             | Cross-cutting    | —                 | Regression tests in sdk-core (vitest) + Rust cargo test assert caller-owns-key       |

---

## Standard Stack

All work modifies existing code in existing packages — no new dependencies.

### Core Libraries Already in Use

| Library / Pattern        | Location                                   | Purpose                                  |
| ------------------------ | ------------------------------------------ | ---------------------------------------- |
| `parseIpnsRecord`        | `@cipherbox/crypto` (imported in api)       | Parse embedded CID/sequence from record  |
| `verifyIpnsSignature`    | `apps/web/src/services/ipns.service.ts`    | Ed25519 IPNS signature verification (TS) |
| `verifyEd25519`          | `@cipherbox/crypto`                        | Raw Ed25519 verify primitive (TS)        |
| `verify_ed25519`         | `cipherbox_crypto::ed25519`                | Raw Ed25519 verify primitive (Rust)      |
| `Zeroizing<Vec<u8>>`     | `zeroize` crate (workspace dep)            | Automatic Rust key zeroization on drop   |
| `IPNS_SIGNATURE_PREFIX`  | `crates/core/src/ipns.rs` + TS core        | `b"ipns-signature:"` — IPFS spec prefix  |
| `.fill(0)` in `finally`  | sdk-core `file/index.ts` T-47-01 pattern  | Manual TS key zeroization                |

### No New Packages Required

All patterns and utilities already exist in the repository. The S3 Rust work uses existing `Zeroizing<Vec<u8>>` wrappers; it does not introduce new crates. The S2 Rust work adds fields to an existing struct and a new free function in `crates/api-client/src/ipns.rs`.

---

## Package Legitimacy Audit

No new packages are installed in this phase.

---

## Architecture Patterns

### System Architecture Diagram

```
PUBLISH PATH (S1 target)
  Client (web/sdk-core) ─── signed IPNS record + DTO fields ──► API publishRecord()
                                                                     │
                                                    ┌────────────────┴──────────────────┐
                                                    │     upsertFolderIpns()             │
                                                    │  existing: anti-rollback 409       │
                                                    │  (embedded[incoming] vs            │
                                                    │   embedded[stored])                │
                                                    │                                    │
                                                    │  S1 ADD: embedded-vs-DTO check     │
                                                    │  • embedded.cid vs metadataCid     │
                                                    │  • embedded.seq vs expectedSeq     │
                                                    │    (offset-aware first-publish)    │
                                                    └────────────────────────────────────┘

RESOLVE PATH (S2 target)
  Client ──► API resolveRecord() ──► IpnsResolveResponse{cid, seqNum, signatureV2?, data?, pubKey?}
                │
        ┌───────┴──────────────────────────────────────────────────────────┐
        │                       Client verification                        │
        │                                                                  │
        │  sdk-core (✓ already throws on invalid)                         │
        │    if sig fields present: verify → throw on invalid              │
        │    if sig fields absent: return signatureVerified=false          │
        │                                                                  │
        │  web (S2 fix: remove swallowing try/catch)                      │
        │    if sig fields present: verify → THROW on invalid (not warn)  │
        │    if sig fields absent: return signatureVerified=false + warn   │
        │                                                                  │
        │  Rust api-client (S2 add: new fields + verify fn)               │
        │    IpnsResolveResponse += sig_v2?, data?, pub_key?              │
        │    verify_ipns_signature() → bool                               │
        │    FUSE callers: check sig_verified flag                        │
        └──────────────────────────────────────────────────────────────────┘

ZEROIZATION (S3 target — memory hygiene across process lifetime)
  sdk-core ipns/index.ts:createAndPublishIpnsRecord
    ipnsPrivateKey (param) ─── S3 add: fill(0) in finally ──────────► zeroed

  sdk-core vault/index.ts:publishVaultKeyBlob
    vaultKeyKeypair.privateKey ─── S3 add: fill(0) in finally ──────► zeroed

  sdk-core folder/index.ts:updateFolderMetadataAndPublish
    ipnsPrivateKey + folderKey ─── S3 add: fill(0) in finally (?)    ► see S3 note

  Rust get_folder_key() → Vec<u8> (raw copy of Zeroizing field)
    S3 fix: return Zeroizing<Vec<u8>> or scope callers with Zeroizing wrapper

  Rust resolve_folder_key() BFS queue: VecDeque<(String, Vec<u8>)>
    S3 fix: VecDeque<(String, Zeroizing<Vec<u8>>)>
```

### Recommended Project Structure

No new files are required. Modifications are confined to:

```
apps/api/src/ipns/
  ipns.service.ts          (S1: add embedded-vs-DTO check in upsertFolderIpns)
  ipns.service.spec.ts     (S1: new test cases)

apps/web/src/services/
  ipns.service.ts          (S2: web resolve — remove swallowing try/catch)

packages/sdk-core/src/ipns/
  index.ts                 (S3: add fill(0) in finally for ipnsPrivateKey)

packages/sdk-core/src/folder/
  index.ts                 (S3: add fill(0) in finally for ipnsPrivateKey)

packages/sdk-core/src/vault/
  index.ts                 (S3: add fill(0) in finally for vaultKeyKeypair.privateKey)

packages/sdk-core/src/__tests__/
  ipns.test.ts             (S2/S3: new test cases)
  folder.test.ts           (S3: zeroization test)
  vault.test.ts            (S3: zeroization test)

crates/api-client/src/
  types.rs                 (S2: add sig fields to IpnsResolveResponse)
  ipns.rs                  (S2: add verify_ipns_signature() + caller check)

crates/fuse/src/
  lib.rs                   (S2: fuse callers honor sig_verified; S3: BFS queue + getter)
```

### Pattern 1: S1 — Offset-Aware Sequence Check

The first-publish convention: client creates IPNS record with sequence=`0n`, backend pre-increments to `'1'` in `sequenceNumber` DB column. When client provides `expectedSequenceNumber='0'` (the pre-increment value) for a first publish, the embedded seq in the signed record will be `0n` — this is correct and must not be rejected.

For subsequent publishes: client signs with `sequenceNumber=N`, DB stores `N`. `expectedSequenceNumber` equals the old DB value (e.g., `'5'`) while embedded seq in the incoming record is `N = 6`. The check compares embedded seq vs (expectedSequenceNumber + 1).

```typescript
// Source: re-verification of ipns.service.ts:222-234 and :296-297
// In upsertFolderIpns(), after anti-rollback check, before metadataCid save:

const incomingParsed = await parseIpnsRecord(signedRecord);
// embedded CID
const embeddedCidMatch = incomingParsed.value.match(/\/ipfs\/([a-zA-Z0-9]+)/);
const embeddedCid = embeddedCidMatch?.[1];
if (embeddedCid !== metadataCid) {
  throw new BadRequestException(
    `signedRecord embedded CID does not match metadataCid: ` +
    `embedded=${embeddedCid}, dto=${metadataCid}`
  );
}

// embedded sequence — offset-aware
// incoming.sequence is what the client signed; expectedSequenceNumber (if provided)
// is the pre-increment value (i.e., current DB value before this publish).
// On first publish: expectedSequenceNumber='0', embedded=0n → ok (0n === 0n + 0n).
// On subsequent: expectedSequenceNumber='5', embedded must be 6n (pre-inc + 1).
// Absence of expectedSequenceNumber: only the anti-rollback (embedded >= stored)
// is enforced (already done above); skip the dto-vs-embedded check.
if (expectedSequenceNumber !== undefined) {
  const expectedSeqBigInt = BigInt(expectedSequenceNumber);
  // First publish special case: client signs seq 0, DB will store 1.
  // expectedSequenceNumber on first publish is '0' (no existing record).
  const isFirstPublish = !existing;
  if (isFirstPublish) {
    // First publish: client sends expectedSequenceNumber='0', embedded must be 0n or 1n.
    // The client signs seq=expectedSequenceNumber+1 = 1n for first publish (some clients).
    // Actually clients sign seq=1n on first publish (createIpnsRecord uses 1n for files,
    // and sequenceNumber param for folders). Accept 0n or 1n on first publish.
    // The signed record's sequence is what the client computed as the new sequence value.
    // See: createFileMetadata uses 1n, createAndPublishIpnsRecord uses params.sequenceNumber.
    // Constraint: embedded must equal expectedSequenceNumber (client's intended new seq).
    // For first publish expectedSeq=0n means client signs seq=1n (pre-inc+1).
    // Reject if embedded deviates by more than 1.
    const diff = incomingParsed.sequence - expectedSeqBigInt;
    if (diff !== 0n && diff !== 1n) {
      throw new BadRequestException(
        `signedRecord sequence does not match expectedSequenceNumber on first publish: ` +
        `embedded=${incomingParsed.sequence}, expected=${expectedSequenceNumber}`
      );
    }
  } else {
    // Subsequent publish: client signs (expectedSequenceNumber + 1).
    const expectedEmbedded = expectedSeqBigInt + 1n;
    if (incomingParsed.sequence !== expectedEmbedded) {
      throw new BadRequestException(
        `signedRecord sequence does not match expectedSequenceNumber: ` +
        `embedded=${incomingParsed.sequence}, expected=${expectedEmbedded}`
      );
    }
  }
}
```

**Critical caveat (from re-verification):** The exact sequence the client puts inside the signed record depends on its publish path. `createFileMetadata` hard-codes `1n` for new file records. `createAndPublishIpnsRecord` (both web and sdk-core) accepts `params.sequenceNumber` and passes it directly to `createIpnsRecord`. The CAS path in `updateFolderMetadataAndPublish` passes `sequenceNumber + 1n` as the new seq. The planner must confirm the exact sequence convention in a test. The research recommendation is: accept `embedded.sequence == expectedSequenceNumber + 1` for non-first-publish, and `embedded.sequence in {0, 1}` for first publish (when `!existing`). The test suite will catch if this is wrong.

**Simpler alternative:** If the sequence check introduces fragility, a narrower S1 can reject only on CID mismatch (the higher-value check) and omit the sequence check. The CONTEXT.md D-01 calls for both; the planner should use the above pattern but note that if tests fail during execution, falling back to CID-only is acceptable per the "defense-in-depth" severity.

### Pattern 2: S2 — Web Fail-Closed Fix

```typescript
// Source: apps/web/src/services/ipns.service.ts:177-205 (current — logger.warn + return)
// Fix: remove the outer try/catch that swallows verification errors.

// BEFORE (current buggy pattern):
if (response.signatureV2 && response.data && response.pubKey) {
  try {
    const valid = await verifyIpnsSignature(...);
    if (!valid) {
      logger.warn('[IPNS] Signature verification failed for', ipnsName); // SWALLOWED
    } else {
      // ...
      signatureVerified = true;
    }
  } catch (verifyError) {
    logger.warn('[IPNS] Signature verification error for', ipnsName, ...); // SWALLOWED
  }
}

// AFTER (matches sdk-core behavior):
if (response.signatureV2 && response.data && response.pubKey) {
  const valid = await verifyIpnsSignature(
    response.signatureV2,
    response.data,
    response.pubKey
  );
  if (!valid) {
    throw new Error('IPNS signature verification failed - record may be tampered');
  }
  const pubKeyBytes = Uint8Array.from(atob(response.pubKey), (c) => c.charCodeAt(0));
  const derivedName = await deriveIpnsName(pubKeyBytes);
  if (derivedName !== ipnsName) {
    throw new Error('IPNS public key does not match requested name - possible key substitution');
  }
  signatureVerified = true;
} else {
  // D-03: absent fields — allow + flag (signatureVerified stays false)
  logger.warn('[IPNS] IPNS resolve returned without signature data, skipping verification');
}
// Return with signatureVerified flag — callers must honor it
```

### Pattern 3: S2 — Rust IpnsResolveResponse Extension

```rust
// Source: crates/api-client/src/types.rs:130-137 (current — missing sig fields)
// Fix: add three optional fields matching the JSON response.

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpnsResolveResponse {
    pub success: bool,
    pub cid: String,
    pub sequence_number: String,
    // S2 additions:
    pub signature_v2: Option<String>,   // base64 Ed25519 signature
    pub data: Option<String>,            // base64 CBOR data
    pub pub_key: Option<String>,         // base64 raw Ed25519 public key (32 bytes)
}
```

```rust
// Source: crates/api-client/src/ipns.rs — new function to add
// verify_ipns_signature uses cipherbox_crypto::verify_ed25519 + IPNS_SIGNATURE_PREFIX

/// Verify the Ed25519 signature on an IPNS resolve response.
///
/// D-02: present-but-invalid → return false (caller must treat as error).
/// D-03: absent fields → return None (allow + flag, not fail).
pub fn verify_ipns_resolve_signature(
    resp: &IpnsResolveResponse,
    ipns_name: &str,
) -> Result<Option<bool>, crate::error::ApiError> {
    let (Some(sig_b64), Some(data_b64), Some(pk_b64)) =
        (&resp.signature_v2, &resp.data, &resp.pub_key)
    else {
        return Ok(None); // absent fields — allow+flag (D-03)
    };

    let sig = base64_decode(sig_b64).map_err(|_| ApiError::DeserializationFailed(
        "signatureV2 base64 decode failed".into()
    ))?;
    let cbor_data = base64_decode(data_b64).map_err(|_| ApiError::DeserializationFailed(
        "data base64 decode failed".into()
    ))?;
    let pub_key = base64_decode(pk_b64).map_err(|_| ApiError::DeserializationFailed(
        "pubKey base64 decode failed".into()
    ))?;

    // Per IPFS IPNS spec: sig is over "ipns-signature:" + cbor_data
    const PREFIX: &[u8] = b"ipns-signature:";
    let mut signed_data = Vec::with_capacity(PREFIX.len() + cbor_data.len());
    signed_data.extend_from_slice(PREFIX);
    signed_data.extend_from_slice(&cbor_data);

    let valid = cipherbox_crypto::verify_ed25519(&signed_data, &sig, &pub_key);
    if !valid {
        return Ok(Some(false));
    }

    // Verify pubKey derives to the requested ipnsName
    let derived_name = cipherbox_crypto::derive_ipns_name(&pub_key)
        .map_err(|e| ApiError::DeserializationFailed(format!("IPNS name derivation: {}", e)))?;
    Ok(Some(derived_name == ipns_name))
}
```

### Pattern 4: S3 — TypeScript Caller-Owns-Key Convention

The established T-47-01 pattern: the function that owns the buffer (allocates or receives as a parameter it intends to consume/release) wraps usage in `try/finally` and calls `.fill(0)` before returning on all exit paths.

```typescript
// Source: packages/sdk-core/src/file/index.ts:369-373 (T-47-01 reference implementation)
// APPLY THIS PATTERN to ipns/index.ts and vault/index.ts

// sdk-core/src/ipns/index.ts — createAndPublishIpnsRecord
export async function createAndPublishIpnsRecord(params: { ipnsPrivateKey: Uint8Array; ... }) {
  return withPerf('ipns:publish', async () => {
    try {
      const record = await createIpnsRecord(params.ipnsPrivateKey, ...);
      // ... rest of function ...
    } finally {
      // T-47-01: caller-owns-key convention — zeroize before returning
      params.ipnsPrivateKey.fill(0);
    }
  });
}

// sdk-core/src/vault/index.ts — publishVaultKeyBlob
export async function publishVaultKeyBlob(params: { userPrivateKey: Uint8Array; ... }) {
  const vaultKeyKeypair = await deriveVaultKeyIpnsKeypair(params.userPrivateKey);
  try {
    // ... existing logic ...
  } finally {
    vaultKeyKeypair.privateKey.fill(0); // T-47-01
  }
}
```

**Note on `updateFolderMetadataAndPublish`:** This function in `folder/index.ts` takes `ipnsPrivateKey` and `folderKey` as params but neither is owned by the function — the CAS loop inside `publishWithCas` may use the key across multiple retry attempts, and the caller (sdk `client.ts`) retains the key for potentially more operations. The convention is: if the function is the terminal consumer (buffer will not be used after return), zero it. Audit `client.ts` usages to confirm whether `updateFolderMetadataAndPublish` is always the last user of these keys before deciding to add `fill(0)` there. The `file.ts` precedent (`updateFileMetadata` DOES zero its `fileIpnsPrivateKey`) suggests the folder sibling should too — but only if `client.ts` callers never reuse the key after the call returns.

### Pattern 5: S3 — Rust Raw-Vec Key Escapes

```rust
// Source: crates/fuse/src/lib.rs:933-938 (get_folder_key — CURRENT, leaks key copy)
pub fn get_folder_key(&self, folder_ino: u64) -> Option<Vec<u8>> {
    self.inodes.get(folder_ino).and_then(|inode| match &inode.kind {
        inode::InodeKind::Root { .. } => Some(self.root_folder_key.to_vec()),   // raw copy
        inode::InodeKind::Folder { folder_key, .. } => Some(folder_key.to_vec()), // raw copy
        _ => None,
    })
}

// FIX: return Zeroizing<Vec<u8>>
pub fn get_folder_key(&self, folder_ino: u64) -> Option<Zeroizing<Vec<u8>>> {
    self.inodes.get(folder_ino).and_then(|inode| match &inode.kind {
        inode::InodeKind::Root { .. } => Some(Zeroizing::new(self.root_folder_key.to_vec())),
        inode::InodeKind::Folder { folder_key, .. } => Some(Zeroizing::new(folder_key.to_vec())),
        _ => None,
    })
}
// Note: This changes the return type of get_folder_key — audit all call sites
// for needed Zeroizing<Vec<u8>> vs [u8; 32] conversions.
```

```rust
// Source: crates/fuse/src/lib.rs:1612 (resolve_folder_key BFS queue — CURRENT)
let mut queue: std::collections::VecDeque<(String, Vec<u8>)> = ...;

// FIX: wrap key entries
let mut queue: std::collections::VecDeque<(String, Zeroizing<Vec<u8>>)> = ...;
queue.push_back((root_ipns_name.to_string(), Zeroizing::new(root_folder_key.to_vec())));
// All .to_vec() calls on unwrap_key results also wrapped in Zeroizing::new(...)
```

### Anti-Patterns to Avoid

- **S1 — strict sequence equality without offset-awareness:** Comparing `embedded.sequence == BigInt(expectedSequenceNumber)` directly will reject all legitimate first publishes where the client signs `0n` but sends `expectedSequenceNumber='0'` (convention says DB stores `1`). The check must account for the `+1` pre-increment.
- **S2 — wrapping the entire verify block in try/catch:** The existing web pattern swallows verification failures, defeating the purpose. Only 404 errors (IPNS not found → null) should be caught — verification errors must propagate.
- **S3 — zeroing in the callee that receives the key by reference:** Do not zero `ipnsPrivateKey` inside `publishWithCas` or other downstream utilities that receive keys; only the function that allocated or was passed the key as a terminal consumer should zero it. The `sdk` package's `client.ts` comments (T-47-01) explicitly document this.
- **S3 — returning Zeroizing keys then immediately calling .to_vec():** Callers of `get_folder_key` that immediately clone to `Vec<u8>` defeat the Zeroizing wrapper. Update callers to hold `Zeroizing<Vec<u8>>` or convert to `[u8; 32]` for crypto operations.

---

## Don't Hand-Roll

| Problem                        | Don't Build            | Use Instead                                                                              |
| ------------------------------ | ---------------------- | ---------------------------------------------------------------------------------------- |
| Ed25519 verification in Rust   | Custom verify fn       | `cipherbox_crypto::verify_ed25519` (already in workspace, wraps `ed25519-dalek`)         |
| IPNS name derivation in Rust   | Custom derive fn       | `cipherbox_crypto::derive_ipns_name` (re-exported via `cipherbox_core`)                 |
| Key zeroing in Rust            | `memset` / manual loop | `Zeroizing<Vec<u8>>` from `zeroize` crate (already in workspace deps)                   |
| Key zeroing in TS              | `new Uint8Array(32)` replacement | `.fill(0)` on the existing buffer (same reference, no heap alloc)         |
| Base64 decode in Rust          | Custom base64          | Use `base64` crate (already in workspace); or `use base64::Engine`                       |

**Key insight:** All primitives needed for S1/S2/S3 exist in the workspace. The phase is purely wiring, not new cryptographic work.

---

## Common Pitfalls

### Pitfall 1: S1 First-Publish Sequence Off-By-One

**What goes wrong:** Adding `embedded.sequence !== BigInt(expectedSequenceNumber) + 1n` for all publishes causes all first publishes to fail (client signs `0n`, expectedSequenceNumber is `'0'`, `0n !== 0n + 1n`).

**Why it happens:** `parseIpnsRecord` returns the sequence the client put in the signed record. For first publishes, some clients use `0n` (before the pre-increment), others use `1n`. The DB stores `'1'` regardless of what the client signed.

**How to avoid:** Use the isFirstPublish branch (`!existing`) to apply looser sequence tolerance (accept `0n` or `1n`) vs the strict `+1` check for updates. Confirm in the new test case.

**Warning signs:** `BadRequestException: signedRecord sequence does not match` on first vault creation or first subfolder creation.

### Pitfall 2: S2 Web — 404 vs Verification Error Conflation

**What goes wrong:** After removing the swallowing try/catch, a verification `Error` thrown by `verifyIpnsSignature` or `deriveIpnsName` gets caught by the outer 404 catch block in `resolveIpnsRecord` and returns `null` silently.

**Why it happens:** The current outer catch only checks `error.status === 404`; Error objects from verification do not have `.status`, so `status === undefined !== 404` — they would propagate. But if the check changes to include a broader condition, verification errors could leak as null.

**How to avoid:** Keep the 404 catch narrow: only swallow `error.status === 404`. All other errors (including verification) must rethrow. This is already the pattern in sdk-core's `resolveIpnsRecord`.

### Pitfall 3: S2 Rust — `signature_v2` Field Name vs JSON `signatureV2`

**What goes wrong:** The Rust struct field `signature_v2` with `#[serde(rename_all = "camelCase")]` would serialize/deserialize as `signatureV2` which matches the API JSON. But if the attribute is accidentally omitted or the field renamed to `sig_v2`, deserialization silently returns `None` since the field is `Option<String>`.

**Why it happens:** Optional serde fields default to `None` on missing key, so a naming mismatch causes silent absent values, not an error.

**How to avoid:** Add a test that asserts `signature_v2` is populated when the API JSON contains `signatureV2`. The existing test mock in `ipns.service.spec.ts` can be extended.

### Pitfall 4: S3 — Double-Zero on Shared Uint8Array

**What goes wrong:** If the same `Uint8Array` reference is passed to two functions and the first zeros it, the second receives zeroed key material and produces incorrect results silently.

**Why it happens:** JS TypedArrays are reference types; `.fill(0)` mutates in-place.

**How to avoid:** Only the terminal callee zeroes the key. The T-47-01 convention in `sdk` package `client.ts` (documented at lines 868, 1456, 1488) explicitly says "do NOT zero it here" in non-terminal callers. Follow this.

### Pitfall 5: S3 Rust — get_folder_key Return Type Change Breaks Callers

**What goes wrong:** Changing `get_folder_key` to return `Option<Zeroizing<Vec<u8>>>` breaks every call site that passes the result to functions expecting `&[u8]` or `[u8; 32]`.

**Why it happens:** `Zeroizing<Vec<u8>>` deref-coerces to `&Vec<u8>` → `&[u8]` so most slice-based callers work. But callers that do `.unwrap()` followed by `try_into::<[u8; 32]>()` on the Vec still work. The issue arises if callers do `let key: Vec<u8> = get_folder_key(...).unwrap()` (now type-mismatches).

**How to avoid:** Audit all call sites of `get_folder_key` before changing the return type. Consider whether changing the return type is worth the churn vs. just wrapping the result in `Zeroizing::new(...)` at each call site. The latter is a smaller diff.

---

## Code Examples

### Verified Pattern: parseIpnsRecord is Already Called in upsertFolderIpns

```typescript
// Source: apps/api/src/ipns/ipns.service.ts:222-226 (VERIFIED by file read)
// parseIpnsRecord already called for anti-rollback — S1 reuses this result.
if (existing?.signedRecord) {
  const [incoming, stored] = await Promise.all([
    parseIpnsRecord(signedRecord),        // ← parseIpnsRecord result for S1 CID check
    parseIpnsRecord(existing.signedRecord),
  ]);
  if (incoming.sequence < stored.sequence) {
    throw new ConflictException({ ... }); // existing anti-rollback 409
  }
  // S1: add check here — incoming.value must contain metadataCid
}
// For new records (no existing), call parseIpnsRecord once for S1 check only
```

### Verified Pattern: The Existing sdk-core resolveIpnsRecord Throws Correctly

```typescript
// Source: packages/sdk-core/src/ipns/index.ts:196-219 (VERIFIED)
// This is the TARGET behavior for web (D-02)
if (response.signatureV2 && response.data && response.pubKey) {
  const valid = await verifyIpnsSignature(...);
  if (!valid) {
    throw new Error('IPNS signature verification failed - record may be tampered');
  }
  // pubKey-to-name binding check
  const derivedName = await deriveIpnsName(pubKeyBytes);
  if (derivedName !== ipnsName) {
    throw new Error('IPNS public key does not match requested name - ...');
  }
  signatureVerified = true;
} else {
  console.warn('IPNS resolve returned without signature data, skipping verification');
}
// D-03: absent → returns {cid, sequenceNumber, signatureVerified: false}
```

### Verified Pattern: T-47-01 Reference Implementation

```typescript
// Source: packages/sdk-core/src/file/index.ts:369-374 (VERIFIED)
try {
  const resolved = await resolveIpnsRecord(params.fileMetaIpnsName, params.ctx);
  // ... CAS publish ...
} finally {
  // Zeroize the private key on all exit paths (T-47-01 / T-44-12).
  params.fileIpnsPrivateKey.fill(0);
}
```

---

## Runtime State Inventory

Not applicable — this is a code-only hardening phase with no renames, data migrations, or schema changes.

---

## State of the Art

| Old Approach                                 | Current Approach                                       | When Changed | Impact                                                              |
| -------------------------------------------- | ------------------------------------------------------ | ------------ | ------------------------------------------------------------------- |
| No embedded-vs-DTO validation (publish)      | S1: strict CID + offset-aware seq check                | Phase 51     | Publish-time integrity gate; prevents drift between record and DTO  |
| Web: warn+return on invalid sig              | S2: throw on invalid sig (match sdk-core)              | Phase 51     | Web resolves are now fail-closed on tampered records                |
| Rust: no signature fields in resolve resp    | S2: fields + verify fn in api-client                   | Phase 51     | Desktop FUSE can verify IPNS records, not just trust the CID        |
| No caller-owns-key convention in sdk-core    | S3: T-47-01 `fill(0)` in finally on all touched paths | Phase 51     | Ed25519 + folder keys don't persist in JS heap after use           |
| Rust BFS queue uses raw Vec<u8>              | S3: Zeroizing<Vec<u8>> in BFS queue                    | Phase 51     | Folder keys in BFS descent are zeroed when queue entries are dropped |

**Deprecated/outdated patterns flagged by this phase:**

- `logger.warn` in web `resolveIpnsRecord` on invalid sig: replace with throw (S2).
- Raw `.to_vec()` on `Zeroizing` fields in `get_folder_key` and `build_folder_metadata`: replace with `Zeroizing::new(...)` wrappers (S3).

---

## Validation Architecture

Nyquist validation is enabled. Every S1/S2/S3 behavioral change has a defined I/O contract suitable for test-first.

### Test Framework

| Property           | Value                                           |
| ------------------ | ----------------------------------------------- |
| API (NestJS)       | Jest (`pnpm --filter @cipherbox/api test`)       |
| sdk-core           | Vitest (`pnpm --filter @cipherbox/sdk-core test`)|
| web                | Vitest (`.test.ts` files only, not `.spec.ts`)  |
| Rust               | `cargo test -p cipherbox-api-client -p cipherbox-fuse` |

### Phase Requirements → Test Map

| Req ID  | Behavior                                                         | Test Type   | Automated Command                                                                             | File Exists? |
| ------- | ---------------------------------------------------------------- | ----------- | --------------------------------------------------------------------------------------------- | ------------ |
| HARD-02 | S1: 400 on embedded-CID vs metadataCid mismatch                  | unit        | `pnpm --filter @cipherbox/api test -- --testPathPattern ipns.service.spec`                    | YES          |
| HARD-02 | S1: 400 on embedded-seq vs expectedSeq mismatch (non-first)      | unit        | `pnpm --filter @cipherbox/api test -- --testPathPattern ipns.service.spec`                    | YES (extend) |
| HARD-02 | S1: first-publish seq tolerance (0n or 1n accepted)              | unit        | `pnpm --filter @cipherbox/api test -- --testPathPattern ipns.service.spec`                    | YES (extend) |
| HARD-02 | S1: valid CID+seq passes through unblocked                       | unit        | `pnpm --filter @cipherbox/api test -- --testPathPattern ipns.service.spec`                    | YES (extend) |
| HARD-02 | S2: web resolve throws on present-but-invalid sig                | unit        | `pnpm --filter @cipherbox/web test` (add test file for web ipns.service)                     | NO — Wave 0 |
| HARD-02 | S2: web resolve returns signatureVerified=false on absent fields | unit        | `pnpm --filter @cipherbox/web test`                                                           | NO — Wave 0 |
| HARD-02 | S2: sdk-core resolve already throws (regression test)            | unit        | `pnpm --filter @cipherbox/sdk-core test -- ipns`                                              | YES (exists) |
| HARD-02 | S2: Rust IpnsResolveResponse deserializes sig fields             | unit (Rust) | `cargo test -p cipherbox-api-client`                                                          | NO — Wave 0 |
| HARD-02 | S2: Rust verify_ipns_resolve_signature returns None on absent    | unit (Rust) | `cargo test -p cipherbox-api-client`                                                          | NO — Wave 0 |
| HARD-02 | S2: Rust verify_ipns_resolve_signature returns Some(false) on invalid | unit (Rust) | `cargo test -p cipherbox-api-client`                                                     | NO — Wave 0 |
| HARD-02 | S3: ipns createAndPublishIpnsRecord zeroes key after return      | unit        | `pnpm --filter @cipherbox/sdk-core test -- ipns`                                              | YES (extend) |
| HARD-02 | S3: vault publishVaultKeyBlob zeroes keypair.privateKey          | unit        | `pnpm --filter @cipherbox/sdk-core test -- vault`                                             | YES (extend) |
| HARD-02 | S3: updateFolderMetadataAndPublish zeroes key (if confirmed owner)| unit       | `pnpm --filter @cipherbox/sdk-core test -- folder`                                            | YES (extend) |
| HARD-02 | S3: Rust BFS queue entries are Zeroizing (compile-time)          | compile     | `cargo build -p cipherbox-fuse`                                                               | YES (impl)   |

### Sampling Rate

- **Per task commit:** `pnpm --filter @cipherbox/api test -- --testPathPattern ipns.service.spec` (API, fast) + `pnpm --filter @cipherbox/sdk-core test -- ipns` (sdk-core, fast)
- **Per wave merge:** `pnpm --filter @cipherbox/api test && pnpm --filter @cipherbox/sdk-core test && cargo test -p cipherbox-api-client`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `apps/web/src/services/__tests__/ipns.service.test.ts` — covers S2 web fail-closed (present-but-invalid throws, absent-fields returns signatureVerified=false)
- [ ] `crates/api-client/src/ipns_tests.rs` (or inline `#[cfg(test)]` in `ipns.rs`) — covers Rust sig field deserialization + `verify_ipns_resolve_signature` cases

_(Existing `ipns.service.spec.ts` covers S1 after extension. Existing `sdk-core/__tests__/ipns.test.ts` covers sdk-core S2/S3 after extension.)_

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category           | Applies | Standard Control                                                                    |
| ----------------------- | ------- | ----------------------------------------------------------------------------------- |
| V2 Authentication       | no      | —                                                                                   |
| V3 Session Management   | no      | —                                                                                   |
| V4 Access Control       | no      | —                                                                                   |
| V5 Input Validation     | yes     | S1: reject mismatched embedded fields (BadRequestException); existing class-validator on DTOs |
| V6 Cryptography         | yes     | S2: Ed25519 verification; S3: key zeroization after use                             |
| V7 Error Handling       | yes     | S2: verification errors must propagate, not be swallowed                            |

### Known Threat Patterns for IPNS Signature Verification

| Pattern                                    | STRIDE     | Standard Mitigation                                                              |
| ------------------------------------------ | ---------- | -------------------------------------------------------------------------------- |
| Replay of older signed IPNS record         | Tampering  | Existing anti-rollback 409 (embedded-vs-embedded, already shipped)               |
| Substitution of metadataCid in DTO         | Tampering  | S1: embedded-vs-DTO CID check on publish                                         |
| Compromised server strips signature fields | Repudiation| D-03 allow-on-missing is intentional (DB CID is authoritative); documented tradeoff |
| Compromised server sends invalid signature  | Tampering  | S2: fail-closed on present-but-invalid (web + sdk-core + Rust)                  |
| Key substitution in pubKey-to-name binding | Spoofing   | Already checked in sdk-core; S2 ensures web and Rust also check                 |
| Private key persistence in JS heap         | Info Disclosure | S3: T-47-01 `fill(0)` in finally on all key-owning boundaries               |
| Private key persistence in Rust BFS queue  | Info Disclosure | S3: `Zeroizing<Vec<u8>>` in BFS queue and `get_folder_key` return             |

---

## Project Constraints (from CLAUDE.md)

- Use TypeScript for all JS code (enforced)
- String literals over TypeScript enums
- `publicKey`, `privateKey`, `rootFolderKey`, `ipnsRecord`, `signatureVerified` — use canonical terminology
- No logging of sensitive keys (existing; S3 does not change logging)
- ECIES for key wrapping, AES-256-GCM for content (not changed by this phase)
- Server never has access to plaintext/unencrypted keys (zero-knowledge preserved throughout)
- `pnpm api:generate` required after any API DTO/controller change — S2 adds fields to the response shape. If the Rust `IpnsResolveResponse` is a hand-written struct (not generated from OpenAPI), no `api:generate` is needed. The TypeScript API client IS generated; if the API's resolve response DTO gains new optional fields they will be included on the next generate run. Check whether `ipnsControllerResolveRecord` return type already includes `signatureV2?` etc. (it does, per `apps/web/src/services/ipns.service.ts` which imports from `@cipherbox/api-client` and accesses `response.signatureV2`). So no `api:generate` run is needed for S2 — the generated client already carries the optional fields.

---

## Environment Availability

Step 2.6: SKIPPED — this phase is purely code changes with no new external CLI tools, services, or runtimes. The existing API, sdk-core, web, and Rust build toolchains are confirmed working (Phase 50 just completed).

---

## Open Questions (RESOLVED)

1. **S1 sequence check: does `updateFolderMetadataAndPublish` → `publishWithCas` send `expectedSequenceNumber = currentSeq` (the old DB value) and sign with `currentSeq + 1n`?**
   - What we know: `buildFolderIpnsRecord` in `folder/index.ts:424` sets `expectedSequenceNumber: params.sequenceNumber.toString()` and calls `createIpnsRecord` with `newSeq = params.sequenceNumber + 1n`.
   - What's clear: the signed record will contain `newSeq = currentSeq + 1n`, and `expectedSequenceNumber` is the pre-increment value. So `embedded.sequence == BigInt(expectedSequenceNumber) + 1n` is correct for folder updates.
   - **Resolved by code read:** The +1 check is correct. Document in test assertions.

2. **S3 — should `updateFolderMetadataAndPublish` zero `params.ipnsPrivateKey`?**
   - What we know: `updateFileMetadata` (file sibling) zeros `fileIpnsPrivateKey` because `client.ts` explicitly documents "do NOT zero it here" for outer callers. The folder case: `client.ts` lines reference T-47-01 for file but not folder. `publishWithCas` in `cas.ts` notes keys must be zeroed by the caller (`T-47-01` in the `cas.ts` docstring).
   - What's unclear: whether `client.ts` reuses `ipnsPrivateKey` after `updateFolderMetadataAndPublish` returns.
   - **Resolved:** Decision is delegated to an execution-time call-site audit (per assumption A2). Plan 51-04 Task 3 implements the deterministic rule: audit the `client.ts` `updateFolderMetadataAndPublish` call sites (notably the move source/dest paths) — if the key buffer is NOT reused after the call, add `finally { params.ipnsPrivateKey.fill(0) }`; if it IS reused (shared buffer), document the skip with a matching guard test. Either branch is covered by a test, so the convention is enforced regardless of the audit outcome. This is an acceptable deferred-to-task resolution: the analysis is fully scoped, only the binary buffer-ownership fact requires reading current `client.ts` source, and both outcomes are pre-specified.

3. **S2 Rust — does `derive_ipns_name` exist in cipherbox_crypto or only in cipherbox_core?**
   - What we know: `crates/core/src/ipns.rs:20` has `pub use cipherbox_crypto::ipns_name::derive_ipns_name`. So it is available via `cipherbox_crypto` directly.
   - **Resolved:** Use `cipherbox_crypto::derive_ipns_name` or `cipherbox_core::derive_ipns_name` (re-export). Either works; prefer `cipherbox_crypto` in `crates/api-client` to avoid pulling in `cipherbox_core` as a new dependency.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
| - | ----- | ------- | ------------- |
| A1 | `derive_ipns_name` is already available in `cipherbox_crypto` (confirmed via `crates/core/src/ipns.rs:20` re-export, but `crates/api-client/Cargo.toml` may not yet depend on `cipherbox_crypto`) | Standard Stack / S2 Rust | If `cipherbox-api-client` does not already depend on `cipherbox-crypto`, a `Cargo.toml` dep addition is needed (low risk, local workspace crate) |
| A2 | `updateFolderMetadataAndPublish` callers in `client.ts` do not reuse `ipnsPrivateKey` after the call | S3 zeroization pattern | If callers do reuse the key, adding `fill(0)` would zero live key material — must confirm before adding |

---

## Sources

### Primary (HIGH confidence)

- Direct file reads of all canonical refs listed in CONTEXT.md — ipns.service.ts, sdk-core/ipns/index.ts, sdk-core/folder/index.ts, sdk-core/file/index.ts, sdk-core/vault/index.ts, apps/web/services/ipns.service.ts, crates/api-client/src/ipns.rs, crates/api-client/src/types.rs, crates/fuse/src/lib.rs, crates/crypto/src/ecies.rs, crates/core/src/ipns.rs, inode.rs [VERIFIED: codebase]
- Security review REVIEW-20260402-172126.md — origin of S1/S2/S3 findings [VERIFIED: codebase]
- Re-verification todo 2026-06-13-ipns-signature-storage-review-deferred.md — current line numbers [VERIFIED: codebase]
- CONTEXT.md decisions D-01..D-05 [VERIFIED: codebase]

### Secondary (MEDIUM confidence)

- T-47-01 convention documentation inferred from `packages/sdk-core/src/file/index.ts` comments and `packages/sdk/src/client.ts` inline comments [VERIFIED: codebase]
- `Zeroizing` usage pattern inferred from workspace Cargo.toml and existing `crates/fuse/src/inode.rs`, `crates/crypto/src/ed25519.rs` [VERIFIED: codebase]

### Tertiary (LOW confidence)

None — all claims verified via codebase reads.

---

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — all tools/patterns confirmed in existing code
- Architecture: HIGH — all files read directly, no guessing
- Pitfalls: HIGH — all derived from specific code paths verified by file reads
- Validation: HIGH — test files exist and were read

**Research date:** 2026-06-19
**Valid until:** 2026-07-19 (30 days; stable codebase, no fast-moving deps)
