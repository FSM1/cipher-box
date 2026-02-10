---
phase: quick-007
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - apps/api/src/ipns/ipns-record-parser.ts
  - apps/api/src/ipns/dto/resolve.dto.ts
  - apps/api/src/ipns/ipns.service.ts
  - apps/api/src/ipns/ipns.controller.ts
  - apps/web/src/services/ipns.service.ts
  - apps/web/src/services/folder.service.ts
  - apps/web/src/components/file-browser/FileBrowser.tsx
  - apps/web/src/components/file-browser/DetailsDialog.tsx
autonomous: true

must_haves:
  truths:
    - 'Resolve response includes signatureV2, data, and pubKey fields from the IPNS record'
    - 'Client verifies Ed25519 signature before trusting the resolved CID'
    - 'Invalid IPNS signature causes folder load to fail with a clear error, not silently use bad data'
    - 'DB-cached fallback resolves still work (signature fields optional in response)'
  artifacts:
    - path: 'apps/api/src/ipns/ipns-record-parser.ts'
      provides: 'Extended parser extracting signatureV2 (field 8), data (field 9), pubKey (field 7)'
      contains: 'signatureV2'
    - path: 'apps/api/src/ipns/dto/resolve.dto.ts'
      provides: 'Response DTO with optional signatureV2, data, pubKey as base64 strings'
      contains: 'signatureV2'
    - path: 'apps/web/src/services/ipns.service.ts'
      provides: 'verifyIpnsSignature function and signature check in resolveIpnsRecord'
      contains: 'verifyEd25519'
  key_links:
    - from: 'apps/api/src/ipns/ipns-record-parser.ts'
      to: 'apps/api/src/ipns/ipns.service.ts'
      via: 'parseIpnsRecord returns signatureV2/data/pubKey'
      pattern: 'signatureV2.*data.*pubKey'
    - from: 'apps/api/src/ipns/ipns.service.ts'
      to: 'apps/api/src/ipns/ipns.controller.ts'
      via: 'resolve result includes signature fields'
      pattern: 'signatureV2'
    - from: 'apps/web/src/services/ipns.service.ts'
      to: '@cipherbox/crypto verifyEd25519'
      via: 'import and call for signature verification'
      pattern: 'verifyEd25519'
---

<objective>
Add client-side IPNS signature validation to prevent metadata tampering (GitHub #71).

Purpose: Currently the client trusts whatever CID the backend returns from IPNS resolution without verifying the IPNS record's cryptographic signature. An attacker who intercepts or modifies the response could feed the client a malicious CID pointing to tampered metadata. By verifying the Ed25519 signature on the IPNS record before trusting the CID, we close this security gap.

Output: Backend returns IPNS record signature data in resolve responses; client verifies Ed25519 signature before using the CID; verification failure throws error and prevents folder load.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@apps/api/src/ipns/ipns-record-parser.ts
@apps/api/src/ipns/dto/resolve.dto.ts
@apps/api/src/ipns/ipns.service.ts
@apps/api/src/ipns/ipns.controller.ts
@apps/web/src/services/ipns.service.ts
@apps/web/src/services/folder.service.ts
@packages/crypto/src/ed25519/sign.ts
@packages/crypto/src/ipns/sign-record.ts
@packages/crypto/src/index.ts
</context>

<tasks>

<task type="auto">
  <name>Task 1: Backend - Extract signature data from IPNS records and include in resolve response</name>
  <files>
    apps/api/src/ipns/ipns-record-parser.ts
    apps/api/src/ipns/dto/resolve.dto.ts
    apps/api/src/ipns/ipns.service.ts
    apps/api/src/ipns/ipns.controller.ts
  </files>
  <action>
**1. Extend `ipns-record-parser.ts`:**

The parser currently extracts only `value` (field 1) and `sequence` (field 5) from the IPNS protobuf. Extend `ParsedIpnsRecord` and the parser to also extract:

- `signatureV2` (protobuf field 8, wire type 2 / length-delimited) - the Ed25519 signature bytes
- `data` (protobuf field 9, wire type 2 / length-delimited) - the CBOR-encoded record data that was signed
- `pubKey` (protobuf field 7, wire type 2 / length-delimited) - the embedded Ed25519 public key (protobuf-encoded)

Add these as `Uint8Array | undefined` fields to `ParsedIpnsRecord`. In the parser loop, capture them when the matching field numbers are encountered (they are all length-delimited / wire type 2).

Note: The `pubKey` field (field 7) is a protobuf-encoded libp2p public key, NOT the raw 32-byte Ed25519 key. The protobuf wrapping is: `[0x08, 0x01, 0x12, 0x20, ...32 bytes of Ed25519 pubkey]`. The first 4 bytes are protobuf framing (field 1 = KeyType.Ed25519, field 2 = 32-byte length-prefixed data). Extract the raw 32 bytes by slicing `pubKey.subarray(4)` when the pubKey has this standard 36-byte format. Do this extraction in the parser helper, returning `pubKey` as the raw 32-byte Ed25519 public key in `ParsedIpnsRecord`.

**2. Update `resolve.dto.ts`:**

Add three optional fields to `ResolveIpnsResponseDto`:

- `signatureV2?: string` — base64-encoded Ed25519 signature (64 bytes)
- `data?: string` — base64-encoded CBOR data that was signed
- `pubKey?: string` — base64-encoded raw Ed25519 public key (32 bytes)

Use `@ApiProperty({ required: false })` and `@IsOptional()` decorators. These are optional because DB-cached fallback resolves won't have signature data.

**3. Update `ipns.service.ts`:**

In `parseIpnsRecordBytes`, after calling `parseIpnsRecord(recordBytes)`, also return `signatureV2`, `data`, and `pubKey` from the parsed result. Update the return type to include these optional fields. Base64-encode them using `Buffer.from(bytes).toString('base64')`.

In `resolveRecord`, when the result comes from `resolveFromDelegatedRouting`, pass through the signature fields. When falling back to DB cache, the signature fields will be undefined (acceptable - client handles this gracefully).

**4. Update `ipns.controller.ts`:**

In the `resolveRecord` method, pass through the optional `signatureV2`, `data`, and `pubKey` fields from the service result to the response DTO. Only include them if they exist (spread conditionally).

**5. Regenerate the API client:**

Run `pnpm api:generate` to regenerate the typed client so the web app picks up the new response fields.

IMPORTANT: After all backend changes, run `pnpm api:generate` before moving to Task 2.
</action>
<verify> - `pnpm --filter api build` compiles without errors - `pnpm api:generate` succeeds and `apps/web/src/api/models/resolveIpnsResponseDto.ts` now includes `signatureV2`, `data`, and `pubKey` optional fields - `pnpm --filter api test` passes (existing tests still green)
</verify>
<done>
The resolve endpoint returns signatureV2, data, and pubKey alongside cid and sequenceNumber when resolving from delegated routing. DB-cached fallback returns only cid and sequenceNumber (no signature data). Generated API client types reflect the new optional fields.
</done>
</task>

<task type="auto">
  <name>Task 2: Client - Verify IPNS signature before trusting CID</name>
  <files>
    apps/web/src/services/ipns.service.ts
    apps/web/src/services/folder.service.ts
    apps/web/src/components/file-browser/FileBrowser.tsx
    apps/web/src/components/file-browser/DetailsDialog.tsx
  </files>
  <action>
**1. Add signature verification to `ipns.service.ts`:**

Add a new exported async function `verifyIpnsSignature`:

```typescript
import { verifyEd25519, IPNS_SIGNATURE_PREFIX, concatBytes } from '@cipherbox/crypto';

/**
 * Verify the Ed25519 signature on an IPNS record.
 * Per IPFS spec, the signature is over "ipns-signature:" + cborData.
 *
 * @param signatureV2 - base64 Ed25519 signature (64 bytes)
 * @param data - base64 CBOR data that was signed
 * @param pubKey - base64 raw Ed25519 public key (32 bytes)
 * @returns true if valid
 */
export async function verifyIpnsSignature(
  signatureV2: string,
  data: string,
  pubKey: string
): Promise<boolean> {
  const sigBytes = Uint8Array.from(atob(signatureV2), (c) => c.charCodeAt(0));
  const dataBytes = Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
  const pubKeyBytes = Uint8Array.from(atob(pubKey), (c) => c.charCodeAt(0));

  // Per IPFS IPNS spec, signature is over "ipns-signature:" + cborData
  const signedData = concatBytes(IPNS_SIGNATURE_PREFIX, dataBytes);
  return verifyEd25519(sigBytes, signedData, pubKeyBytes);
}
```

**2. Update `resolveIpnsRecord` in `ipns.service.ts`:**

After receiving the API response, if `signatureV2`, `data`, and `pubKey` are all present, call `verifyIpnsSignature`. If verification returns false, throw an error: `'IPNS signature verification failed - record may be tampered'`. If signature fields are missing (DB-cached fallback), skip verification and continue as before (log a warning: `'IPNS resolve returned without signature data, skipping verification'`).

Update the return type to include the signature verification status:

```typescript
export async function resolveIpnsRecord(
  ipnsName: string
): Promise<{ cid: string; sequenceNumber: bigint; signatureVerified: boolean } | null>;
```

Return `signatureVerified: true` when signature checked and valid, `signatureVerified: false` when signature data not available (DB cache fallback). This way callers can log/track but don't need to handle it differently.

**3. Update callers in `folder.service.ts`:**

In `loadFolder` (line ~79), no changes needed to the logic since `resolveIpnsRecord` already throws on invalid signature. The `resolved` object now includes `signatureVerified` but `loadFolder` only uses `cid` and `sequenceNumber`. No destructuring changes needed if using dot notation (`resolved.cid`, `resolved.sequenceNumber`).

**4. Update callers in `FileBrowser.tsx`:**

In the `handleSync` callback (line ~164), same as above - `resolveIpnsRecord` throws on invalid signature, so existing error handling (the try/catch in useSyncPolling) will catch it. The `resolved.sequenceNumber` access remains the same. No changes needed.

**5. Update callers in `DetailsDialog.tsx`:**

In `DetailsDialog.tsx` (line ~279), same pattern - the call to `resolveIpnsRecord` will throw on invalid signature. No changes needed since existing `.then()/.catch()` chain handles errors.

**Key design decisions:**

- Do NOT use `concatBytes` from `@cipherbox/crypto` if it's not exported. Check if it is. If not, just build the concatenation manually with `new Uint8Array(IPNS_SIGNATURE_PREFIX.length + dataBytes.length)` and `.set()` calls (same pattern as `signIpnsData` in `sign-record.ts`).
- `verifyEd25519` returns false on failure (not exception) per decision in 03-02.
- Signature verification failure throws an Error (not a CryptoError) since this is application-level validation, not a crypto operation failure.
  </action>
  <verify>
  - `pnpm --filter web build` compiles without errors (TypeScript checks pass)
  - `pnpm --filter @cipherbox/crypto test` passes
  - Manually inspect that `resolveIpnsRecord` now verifies signature when present and throws on invalid
    </verify>
    <done>
    Client verifies Ed25519 signature on IPNS records before trusting the CID. Invalid signatures throw an error that prevents folder loading. DB-cached fallback resolves (no signature data) proceed with a warning log. All existing callers of `resolveIpnsRecord` work unchanged since the function still returns the same `cid`/`sequenceNumber` shape and throws on errors.
    </done>
    </task>

</tasks>

<verification>
1. `pnpm --filter api build` - API compiles
2. `pnpm --filter api test` - API tests pass
3. `pnpm --filter web build` - Web app compiles with updated types
4. `pnpm --filter @cipherbox/crypto test` - Crypto tests pass
5. Review that `resolveIpnsRecord` in `ipns.service.ts` calls `verifyIpnsSignature` when signature data is present
6. Review that invalid signature throws and prevents `fetchAndDecryptMetadata` from being called
7. Review that DB-cached fallback (no signature data) logs a warning but doesn't throw
</verification>

<success_criteria>

- Backend resolve endpoint returns `signatureV2`, `data`, and `pubKey` (base64) from delegated routing responses
- Client `resolveIpnsRecord` verifies Ed25519 signature over `"ipns-signature:" + data` using `pubKey` before returning CID
- Invalid signature throws error, preventing use of potentially tampered CID
- DB-cached fallback (no signature fields) works with warning log
- All builds compile, all existing tests pass
- Generated API client types include the new optional fields
  </success_criteria>

<output>
After completion, create `.planning/quick/007-client-side-ipns-signature-validation/007-SUMMARY.md`
</output>
