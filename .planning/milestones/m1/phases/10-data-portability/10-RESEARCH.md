# Phase 10: Data Portability - Research

**Researched:** 2026-02-11
**Domain:** Vault export, standalone crypto recovery tool, technical documentation
**Confidence:** HIGH

## Summary

Phase 10 implements data portability: a vault export endpoint on the API, an export button in the web app settings page, a standalone HTML recovery tool, and technical documentation of the export format. The research covers the existing codebase deeply -- the vault entity, crypto module internals, folder traversal logic, ECIES binary format, and IPNS resolution flow -- to determine exactly what needs building and what can be reused.

The export is minimal by design: `rootIpnsName`, `encryptedRootFolderKey`, and `encryptedRootIpnsPrivateKey` (all hex-encoded). No subfolder keys, no CID lists, no plaintext metadata. Recovery works by ECIES-decrypting root keys, then recursively traversing IPNS to discover the entire folder tree and decrypt all files.

The recovery tool must be a single static HTML file that reimplements the relevant portions of `@cipherbox/crypto` using browser-native Web Crypto API and libraries loaded from CDN (noble-curves, noble-hashes, noble-ciphers for the ECIES unwrap; fflate for zip creation). The key challenge is faithfully reimplementing the eciesjs v0.4.16 ECIES unwrap algorithm.

**Primary recommendation:** Build the export endpoint first (simple DB read + JSON response), then the settings UI export button, then the standalone recovery HTML (hardest piece), and finally the format documentation with test vectors.

## Standard Stack

### Core (No new dependencies needed for export)

| Library                      | Version  | Purpose                                           | Why Standard                           |
| ---------------------------- | -------- | ------------------------------------------------- | -------------------------------------- |
| NestJS (existing)            | existing | API endpoint for `GET /user/export-vault`         | Already used for all API endpoints     |
| React (existing)             | existing | Settings page export button + confirmation dialog | Already used for web app               |
| @cipherbox/crypto (existing) | 0.4.0    | Reference implementation for recovery docs        | Already contains all crypto primitives |

### Recovery Tool (standalone HTML, loaded from CDN)

| Library                      | Version | Purpose                                           | CDN URL                                                  |
| ---------------------------- | ------- | ------------------------------------------------- | -------------------------------------------------------- |
| @noble/curves (secp256k1)    | latest  | ECDH key agreement for ECIES unwrap               | `https://cdn.jsdelivr.net/npm/@noble/curves/+esm`        |
| @noble/hashes (sha256, hkdf) | latest  | HKDF-SHA256 key derivation for ECIES unwrap       | `https://cdn.jsdelivr.net/npm/@noble/hashes/+esm`        |
| @noble/ciphers (aes)         | latest  | AES-256-GCM decryption for ECIES and file content | `https://cdn.jsdelivr.net/npm/@noble/ciphers/+esm`       |
| fflate                       | 0.8.x   | Zip file creation for folder download             | `https://cdn.jsdelivr.net/npm/fflate@0.8.2/umd/index.js` |

### Alternatives Considered

| Instead of          | Could Use           | Tradeoff                                                                                                                      |
| ------------------- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| CDN-loaded noble-\* | Web Crypto API only | Web Crypto cannot do secp256k1 ECDH (no secp256k1 support). Must use noble-curves.                                            |
| fflate              | JSZip               | JSZip is 100KB+; fflate is 31KB UMD (11.5KB gzipped). fflate is lighter for single-file embed.                                |
| CDN links           | Inline all JS       | Could inline for truly zero-dependency, but noble-curves alone is ~100KB. CDN is more practical. Could offer both as options. |

## Architecture Patterns

### 1. API Export Endpoint

The `GET /user/export-vault` endpoint is a simple authenticated read. It queries the vault entity and returns a JSON response with hex-encoded fields.

**Location:** New endpoint in `apps/api/src/vault/vault.controller.ts` (add to existing VaultController)
**Or:** New `user` controller if following the API spec exactly (`GET /user/export-vault`)

The existing `VaultService.getVault()` already returns all needed data. The export endpoint is essentially a reformatted version of `GET /vault` with:

- Version identifier added
- Timestamp added
- Different field selection (exclude `teeKeys`, `rootIpnsPublicKey` not needed per CONTEXT.md)
- Instructions string added

**Vault entity fields available (from `apps/api/src/vault/entities/vault.entity.ts`):**

```text
encryptedRootFolderKey: Buffer (BYTEA) -- hex at API boundary
encryptedRootIpnsPrivateKey: Buffer (BYTEA) -- hex at API boundary
rootIpnsName: string (VARCHAR)
rootIpnsPublicKey: Buffer (BYTEA) -- NOT included in export per CONTEXT.md
ownerPublicKey: Buffer (BYTEA) -- NOT included per CONTEXT.md
```

**Export JSON format (per CONTEXT.md decisions):**

```json
{
  "format": "cipherbox-vault-export",
  "version": "1.0",
  "exportedAt": "2026-02-11T12:00:00.000Z",
  "rootIpnsName": "k51qzi5uqu5...",
  "encryptedRootFolderKey": "04a1b2c3...hex...",
  "encryptedRootIpnsPrivateKey": "04d5e6f7...hex..."
}
```

Note: The API spec shows `pinnedCids` in the export. Per CONTEXT.md, the user decided **no CID list**. The export deviates from the API spec intentionally -- CIDs are discovered via IPNS traversal.

### 2. Settings Page Integration

**Existing settings page:** `apps/web/src/routes/SettingsPage.tsx`

- Uses `AppShell` wrapper (sidebar + layout)
- Currently only contains `LinkedMethods` component
- Export button should be a new section below LinkedMethods

**Pattern:**

```tsx
// In SettingsPage.tsx, add new section:
<section className="settings-section">
  <VaultExport />
</section>
```

The `VaultExport` component:

1. Renders "Export Vault" button
2. On click: shows confirmation dialog with security warning
3. On confirm: calls `GET /user/export-vault` (or `GET /vault/export`)
4. On success: triggers browser download of `cipherbox-vault-export.json`

### 3. Recovery Tool Architecture

Single HTML file with embedded CSS and JS. Uses ESM imports from CDN for crypto libraries.

**Recovery flow (mirrors DATA_FLOWS.md section 5.2):**

1. User loads export JSON (file input or paste)
2. User provides private key (hex/base64 paste or file upload)
3. Tool derives public key from private key (secp256k1)
4. Tool ECIES-decrypts `encryptedRootFolderKey` -> `rootFolderKey` (32-byte AES key)
5. Tool ECIES-decrypts `encryptedRootIpnsPrivateKey` -> `rootIpnsPrivateKey` (32-byte Ed25519 seed)
6. Tool resolves `rootIpnsName` via public IPFS gateway -> gets CID of root metadata
7. Tool fetches root metadata from IPFS gateway -> gets encrypted JSON blob
8. Tool decrypts metadata with `rootFolderKey` (AES-256-GCM) -> gets folder children
9. For each subfolder child: ECIES-unwrap its `folderKeyEncrypted` and `ipnsPrivateKeyEncrypted`, resolve IPNS, decrypt metadata, recurse
10. For each file child: ECIES-unwrap `fileKeyEncrypted`, fetch encrypted file from IPFS by CID, decrypt with AES-256-GCM
11. Build zip with folder structure, trigger download

**IPNS resolution without CipherBox API:**
The recovery tool cannot use `GET /ipns/resolve` (CipherBox API). It must use public IPFS gateways or delegated routing directly:

- Option A: `https://delegated-ipfs.dev/routing/v1/ipns/{name}` (delegated routing API)
- Option B: `https://ipfs.io/api/v0/name/resolve?arg={name}` (Kubo-compatible gateway)
- Option C: User-configurable gateway URL

**IPFS content fetch without CipherBox API:**

- `https://ipfs.io/ipfs/{cid}` or `https://dweb.link/ipfs/{cid}` or any public gateway
- Should allow user to configure gateway URL

### 4. Encrypted Folder Metadata Format

The recovery tool must understand the encrypted metadata format stored on IPFS:

```json
{
  "iv": "hex-encoded 12-byte IV",
  "data": "base64-encoded AES-GCM ciphertext (includes 16-byte auth tag)"
}
```

After AES-256-GCM decryption with the folder key:

```json
{
  "version": "v1",
  "children": [
    {
      "type": "folder",
      "id": "uuid",
      "name": "Documents",
      "ipnsName": "k51...",
      "ipnsPrivateKeyEncrypted": "hex ECIES blob",
      "folderKeyEncrypted": "hex ECIES blob",
      "createdAt": 1705268100,
      "modifiedAt": 1705268100
    },
    {
      "type": "file",
      "id": "uuid",
      "name": "photo.jpg",
      "cid": "bafy...",
      "fileKeyEncrypted": "hex ECIES blob",
      "fileIv": "hex 12-byte IV",
      "encryptionMode": "GCM",
      "size": 2048576,
      "createdAt": 1705268100,
      "modifiedAt": 1705268100
    }
  ]
}
```

### Anti-Patterns to Avoid

- **Do NOT inline noble-curves source code** in the HTML file. It is ~100KB of JS. Use CDN imports with integrity hashes.
- **Do NOT use eciesjs directly** in the recovery tool. It requires build tooling. Instead, reimplement the ECIES unwrap using noble-curves + noble-hashes + noble-ciphers (same underlying libraries eciesjs uses).
- **Do NOT omit the `format` field** from export JSON. The recovery tool must validate it.
- **Do NOT fetch from CipherBox API** in the recovery tool. The entire point is infrastructure independence.

## Don't Hand-Roll

| Problem               | Don't Build                | Use Instead                                             | Why                                                                                                 |
| --------------------- | -------------------------- | ------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| ECIES decryption      | Custom ECDH + HKDF + AES   | Reimplement eciesjs algorithm using noble-\* primitives | eciesjs has a specific format (ephemeralPK \|\| nonce \|\| tag \|\| ciphertext); must match exactly |
| AES-256-GCM           | Custom cipher              | Web Crypto API (`crypto.subtle`)                        | Native, hardware-accelerated, available in all modern browsers                                      |
| Zip file creation     | Custom zip builder         | fflate from CDN                                         | Zip format has complex headers, checksums, directory structures                                     |
| Hex encoding/decoding | Manual string manipulation | Standard hexToBytes/bytesToHex utilities                | Easy to get wrong with edge cases                                                                   |
| secp256k1 ECDH        | Custom elliptic curve math | noble-curves secp256k1                                  | Audited, used by eciesjs internally                                                                 |

**Key insight:** The ECIES unwrap in the recovery tool is the critical piece. It must produce byte-identical results to `eciesjs@0.4.16 decrypt()`. This is achievable because eciesjs internally uses noble-curves, noble-hashes, and noble-ciphers -- the same libraries we load from CDN.

## Common Pitfalls

### Pitfall 1: eciesjs ECIES Binary Format Mismatch

**What goes wrong:** The recovery tool fails to decrypt ECIES-wrapped keys because the binary format parsing is wrong.
**Why it happens:** eciesjs v0.4.16 uses a non-standard nonce size (16 bytes for AES-256-GCM instead of the typical 12 bytes) and a specific byte ordering.
**How to avoid:** The exact format is (verified from source code):

```text
ECIES ciphertext layout (eciesjs@0.4.16 default config):
  [65 bytes] ephemeral uncompressed secp256k1 public key (0x04 prefix)
  [16 bytes] AES-256-GCM nonce (NOT 12 bytes!)
  [16 bytes] AES-256-GCM authentication tag
  [N bytes]  AES-256-GCM ciphertext (same length as plaintext)

Key derivation:
  sharedPoint = ECDH(ephemeralPrivateKey, receiverPublicKey) -- uncompressed
  senderPoint = ephemeralPublicKey -- uncompressed (65 bytes)
  ikm = concat(senderPoint, sharedPoint)
  sharedKey = HKDF-SHA256(ikm=ikm, salt=undefined, info=undefined, length=32)

Decryption:
  aesKey = sharedKey (32 bytes)
  nonce = ciphertext[65:81]
  tag = ciphertext[81:97]
  encrypted = ciphertext[97:]
  plaintext = AES-256-GCM-Decrypt(aesKey, nonce, concat(encrypted, tag))
```

**Warning signs:** "Decryption failed" errors when testing with real vault data.

### Pitfall 2: HKDF Salt/Info Parameters

**What goes wrong:** HKDF produces wrong derived key.
**Why it happens:** eciesjs calls `hkdf(sha256, ikm, undefined, undefined, 32)` -- salt and info are both `undefined`, meaning empty. Some HKDF implementations treat `undefined` differently from empty byte array.
**How to avoid:** Use `@noble/hashes/hkdf` with explicit empty parameters, matching eciesjs exactly:

```javascript
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
const key = hkdf(sha256, ikm, undefined, undefined, 32);
```

### Pitfall 3: AES-GCM Tag Handling

**What goes wrong:** AES-256-GCM decryption fails because tag is not in the expected position.
**Why it happens:** Web Crypto API expects `ciphertext || tag` concatenated, while eciesjs stores `nonce || tag || ciphertext` in the ECIES blob. The recovery tool must reconstruct `ciphertext || tag` before calling Web Crypto.
**How to avoid:** When using Web Crypto API for the inner AES-GCM decryption within ECIES:

```javascript
// eciesjs format: nonce || tag || ciphertext
// Web Crypto expects: ciphertext || tag
const combined = new Uint8Array(ciphertext.length + tag.length);
combined.set(ciphertext, 0);
combined.set(tag, ciphertext.length);
// Now pass combined to crypto.subtle.decrypt
```

Alternatively, use `@noble/ciphers` `aes256gcm` which matches eciesjs behavior exactly (it uses this internally).

### Pitfall 4: IPNS Resolution Without Backend

**What goes wrong:** Recovery tool cannot resolve IPNS names because public gateways are unreliable or rate-limited.
**Why it happens:** The web app uses the CipherBox backend as an IPNS relay. The recovery tool has no backend.
**How to avoid:**

- Provide multiple gateway options (delegated-ipfs.dev, ipfs.io, dweb.link)
- Allow user to configure a custom gateway URL
- Implement retry with exponential backoff
- Show clear error messages when resolution fails with gateway alternatives

### Pitfall 5: Ed25519 Private Key Format (32 vs 64 bytes)

**What goes wrong:** Recovery tool tries to use 32-byte Ed25519 seed but IPNS private key is stored as 64 bytes (libp2p format).
**Why it happens:** CipherBox stores IPNS private keys in libp2p format: `privateKey (32 bytes) || publicKey (32 bytes)` = 64 bytes total. The ECIES-wrapped value is this 64-byte blob.
**How to avoid:** After ECIES-unwrapping, the result is 64 bytes. The first 32 bytes are the Ed25519 private key seed; the last 32 bytes are the Ed25519 public key. The recovery tool only needs the key for IPNS name verification (not signing), but if needed for future use, extract the seed (first 32 bytes).

### Pitfall 6: secp256k1 Public Key Derivation for ECIES Shared Point

**What goes wrong:** Recovery tool computes wrong ECDH shared point because it uses compressed keys.
**Why it happens:** eciesjs default config has `isHkdfKeyCompressed: false` and `isEphemeralKeyCompressed: false`. The shared point and sender point are both uncompressed (65 bytes).
**How to avoid:** Always use uncompressed format for ECDH shared point computation. The `getSharedSecret(sk, pk, false)` call in noble-curves returns uncompressed by default, but be explicit.

### Pitfall 7: Base64 vs Hex Encoding Confusion

**What goes wrong:** Wrong encoding used for different fields.
**Why it happens:** The codebase uses two encodings:

- **Hex:** All API boundary fields (`encryptedRootFolderKey`, `encryptedRootIpnsPrivateKey`, `rootIpnsName`, subfolder `folderKeyEncrypted`, `ipnsPrivateKeyEncrypted`, `fileKeyEncrypted`, `fileIv`)
- **Base64:** The `data` field in `EncryptedFolderMetadata` (the encrypted folder content blob)

**How to avoid:** Document encoding per field. Export JSON uses hex. Folder metadata `data` field uses base64.

## Code Examples

### ECIES Unwrap (Recovery Tool Reimplementation)

```javascript
// Reimplement eciesjs@0.4.16 decrypt() using noble-* primitives
// Source: Verified from node_modules/.pnpm/eciesjs@0.4.16

import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { concatBytes } from '@noble/hashes/utils';

async function eciesDecrypt(privateKeyBytes, encryptedData) {
  // 1. Extract ephemeral public key (65 bytes, uncompressed)
  const ephemeralPK = encryptedData.slice(0, 65);
  const encryptedPayload = encryptedData.slice(65);

  // 2. Compute ECDH shared point (uncompressed)
  const sharedPoint = secp256k1.getSharedSecret(privateKeyBytes, ephemeralPK, false);

  // 3. Compute sender point (= ephemeral PK, uncompressed)
  const senderPoint = ephemeralPK;

  // 4. Derive shared key via HKDF-SHA256
  const ikm = concatBytes(senderPoint, sharedPoint);
  const sharedKey = hkdf(sha256, ikm, undefined, undefined, 32);

  // 5. Extract nonce (16 bytes), tag (16 bytes), ciphertext
  const nonce = encryptedPayload.slice(0, 16);
  const tag = encryptedPayload.slice(16, 32);
  const ciphertext = encryptedPayload.slice(32);

  // 6. Decrypt with AES-256-GCM
  // noble-ciphers expects ciphertext || tag
  const { aes_256_gcm } = await import('@noble/ciphers/aes');
  // Or use Web Crypto with reconstructed ciphertext||tag
  const combined = concatBytes(ciphertext, tag);
  const cryptoKey = await crypto.subtle.importKey('raw', sharedKey, { name: 'AES-GCM' }, false, [
    'decrypt',
  ]);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    cryptoKey,
    combined
  );

  return new Uint8Array(plaintext);
}
```

### AES-256-GCM Folder Metadata Decryption

```javascript
// Decrypt folder metadata (matches packages/crypto/src/folder/metadata.ts)
async function decryptFolderMetadata(encryptedJson, folderKey) {
  // encryptedJson = { iv: "hex", data: "base64" }
  const iv = hexToBytes(encryptedJson.iv); // 12 bytes
  const ciphertext = base64ToBytes(encryptedJson.data); // includes 16-byte auth tag

  const cryptoKey = await crypto.subtle.importKey('raw', folderKey, { name: 'AES-GCM' }, false, [
    'decrypt',
  ]);

  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, cryptoKey, ciphertext);

  return JSON.parse(new TextDecoder().decode(plaintext));
}
```

### AES-256-GCM File Decryption

```javascript
// Decrypt file content (matches packages/crypto/src/aes/decrypt.ts)
async function decryptFile(encryptedBytes, fileKey, fileIvHex) {
  const iv = hexToBytes(fileIvHex); // 12 bytes

  const cryptoKey = await crypto.subtle.importKey('raw', fileKey, { name: 'AES-GCM' }, false, [
    'decrypt',
  ]);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    cryptoKey,
    encryptedBytes
  );

  return new Uint8Array(plaintext);
}
```

### Export Endpoint (API)

```typescript
// In vault.controller.ts or new user.controller.ts
@Get('export')
@ApiOperation({ summary: 'Export vault for independent recovery' })
@ApiResponse({ status: 200, description: 'Vault export JSON' })
async exportVault(@Request() req: RequestWithUser) {
  const vault = await this.vaultService.getVault(req.user.id);
  return {
    format: 'cipherbox-vault-export',
    version: '1.0',
    exportedAt: new Date().toISOString(),
    rootIpnsName: vault.rootIpnsName,
    encryptedRootFolderKey: vault.encryptedRootFolderKey,
    encryptedRootIpnsPrivateKey: vault.encryptedRootIpnsPrivateKey,
  };
}
```

### Settings Page Export Button

```tsx
function VaultExport() {
  const [showDialog, setShowDialog] = useState(false);
  const [exporting, setExporting] = useState(false);

  const handleExport = async () => {
    setExporting(true);
    try {
      const response = await vaultControllerExportVault();
      const blob = new Blob([JSON.stringify(response, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'cipherbox-vault-export.json';
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
      setShowDialog(false);
    }
  };

  return (
    <div>
      <h3>Vault Export</h3>
      <p>Export your vault data for independent recovery.</p>
      <button onClick={() => setShowDialog(true)}>Export Vault</button>
      {showDialog && (
        <ConfirmDialog
          title="Export Vault"
          message="This export contains encrypted keys. Store it securely (external drive, password manager). Anyone with this file AND your private key can access your vault."
          onConfirm={handleExport}
          onCancel={() => setShowDialog(false)}
          loading={exporting}
        />
      )}
    </div>
  );
}
```

## State of the Art

| Old Approach             | Current Approach                                      | When Changed        | Impact                                               |
| ------------------------ | ----------------------------------------------------- | ------------------- | ---------------------------------------------------- |
| Export all CIDs in vault | Minimal export (IPNS name + encrypted root keys only) | CONTEXT.md decision | Recovery tool must traverse IPNS to discover content |
| Desktop + web export     | Web-only export for v1                                | CONTEXT.md decision | Simplifies scope; desktop users use web app          |
| Build-step recovery app  | Single static HTML                                    | CONTEXT.md decision | Must use CDN for crypto libraries; no npm/bundler    |

**Key codebase facts (verified from source):**

- eciesjs v0.4.16 is installed (via pnpm)
- eciesjs uses 16-byte AES-GCM nonce (NOT 12-byte), configured in `dist/config.js`
- eciesjs binary format: `ephemeralPK(65) || nonce(16) || tag(16) || ciphertext(N)`
- eciesjs HKDF: `hkdf(sha256, concat(senderPoint, sharedPoint), undefined, undefined, 32)` -- no salt, no info
- eciesjs uses uncompressed keys for both ephemeral and HKDF computation
- Folder metadata uses `EncryptedFolderMetadata` format: `{ iv: "hex", data: "base64" }`
- Folder metadata AES-256-GCM uses standard 12-byte IV (from `generateIv()`)
- File encryption uses AES-256-GCM with 12-byte IV
- IPNS private keys stored as 64-byte libp2p format (seed || pubkey)
- Vault entity stores all keys as BYTEA, hex-encoded at API boundary
- Settings page exists at `apps/web/src/routes/SettingsPage.tsx`, uses `AppShell` wrapper
- No export endpoint exists yet; no user controller exists
- HashRouter is used (IPFS-compatible)
- Web app uses `customInstance` (fetch-based) and some direct axios calls for file operations

## Open Questions

1. **Gateway for IPNS resolution in recovery tool**
   - What we know: delegated-ipfs.dev is used by the backend for IPNS resolution, but it has been unreliable (see `IPNS resolve 502` known bug in memory)
   - What's unclear: Which public gateway(s) are most reliable for IPNS resolution without authentication?
   - Recommendation: Default to `https://delegated-ipfs.dev` but allow user-configurable gateway. Include `ipfs.io` and `dweb.link` as alternatives. Test with real IPNS names during implementation.

2. **API endpoint path: `/vault/export` vs `/user/export-vault`**
   - What we know: API spec says `GET /user/export-vault`, but no user controller exists. Vault controller exists at `/vault`.
   - What's unclear: Whether to create a new user module or add to vault controller
   - Recommendation: Add `GET /vault/export` to existing `VaultController` for simplicity. The endpoint semantically belongs with vault operations. Update API client generation.

3. **Auth method derivation hints in export**
   - What we know: CONTEXT.md lists this as "Claude's discretion"
   - Recommendation: Include a simple `derivationInfo` field: `{ "method": "web3auth" | "external-wallet", "derivationVersion": 1 | null }`. This helps recovery by telling the user how their key was derived, without leaking sensitive info. The user entity has `derivationVersion` (null for social login, 1+ for external wallet).

4. **Noble-ciphers AES-256-GCM vs Web Crypto API for ECIES unwrap**
   - What we know: eciesjs uses `@noble/ciphers/aes` `aes256gcm` internally. Web Crypto API supports AES-256-GCM.
   - Key difference: eciesjs uses 16-byte nonce for AES-256-GCM. Web Crypto API supports non-standard nonce lengths for AES-GCM.
   - Recommendation: Use `@noble/ciphers` for the ECIES inner AES-256-GCM (matches eciesjs exactly). Use Web Crypto API for folder metadata and file content decryption (12-byte standard IV). This avoids any subtle compatibility issues.

## Sources

### Primary (HIGH confidence)

- Codebase: `packages/crypto/src/` -- all crypto modules, types, constants
- Codebase: `apps/api/src/vault/` -- vault entity, service, controller, DTOs
- Codebase: `apps/web/src/services/folder.service.ts` -- folder traversal, metadata format
- Codebase: `apps/web/src/hooks/useFolderNavigation.ts` -- subfolder loading flow
- Codebase: `apps/web/src/routes/SettingsPage.tsx` -- existing settings page
- Codebase: `node_modules/.pnpm/eciesjs@0.4.16/` -- verified ECIES binary format, HKDF params, nonce size
- Spec: `00-Preliminary-R&D/Documentation/API_SPECIFICATION.md` -- export endpoint spec
- Spec: `00-Preliminary-R&D/Documentation/DATA_FLOWS.md` -- section 5.2 recovery flow

### Secondary (MEDIUM confidence)

- [eciesjs GitHub DETAILS.md](https://github.com/ecies/js/blob/master/DETAILS.md) -- confirmed ECIES format documentation
- [fflate CDN on jsDelivr](https://www.jsdelivr.com/package/npm/fflate) -- CDN availability confirmed
- [noble-curves CDN on jsDelivr](https://www.jsdelivr.com/package/npm/@noble/curves) -- CDN availability confirmed

### Tertiary (LOW confidence)

- IPNS public gateway reliability -- anecdotal from known bugs, needs testing

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- verified all from codebase, no new libraries for core functionality
- Architecture: HIGH -- existing patterns well understood, export is straightforward
- ECIES format: HIGH -- verified directly from installed eciesjs@0.4.16 source code
- Recovery tool crypto: HIGH -- verified algorithm by reading eciesjs dist/\*.js files
- IPNS gateway reliability: LOW -- needs runtime testing
- Pitfalls: HIGH -- derived from actual source code analysis

**Research date:** 2026-02-11
**Valid until:** 90 days (stable domain, no expected breaking changes)
