# Phase 3: Core Encryption - Research

**Researched:** 2026-01-20
**Domain:** Client-side cryptography - AES-256-GCM, ECIES secp256k1, Ed25519, HKDF
**Confidence:** HIGH

## Summary

Phase 3 implements the `@cipherbox/crypto` package, providing all cryptographic primitives for client-side encryption. The research confirms a clear standard stack using the `@noble/*` family of libraries combined with the native Web Crypto API.

The recommended approach:

- **AES-256-GCM** - Use Web Crypto API (native, hardware-accelerated) for file/metadata encryption
- **ECIES secp256k1** - Use `eciesjs` library (built on `@noble/curves` + `@noble/ciphers`) for key wrapping
- **Ed25519** - Use `@noble/ed25519` for IPNS record signing (faster, smaller than `@libp2p/crypto`)
- **HKDF-SHA256** - Use Web Crypto API (native) for key hierarchy derivation

**Primary recommendation:** Build the crypto module using Web Crypto API for symmetric operations (AES-GCM, HKDF) and `@noble/*` + `eciesjs` for elliptic curve operations. This provides audited, performant implementations with minimal dependencies.

## Standard Stack

The established libraries/tools for this domain:

### Core

| Library          | Version | Purpose                                       | Why Standard                                                     |
| ---------------- | ------- | --------------------------------------------- | ---------------------------------------------------------------- |
| Web Crypto API   | Native  | AES-256-GCM, HKDF-SHA256, random bytes        | Browser-native, hardware-accelerated, audited by browser vendors |
| eciesjs          | ^0.4.16 | ECIES encryption/decryption (secp256k1)       | Built on @noble/\*, audited, browser-friendly, single API        |
| @noble/ed25519   | ^2.x    | Ed25519 key generation, signing, verification | Audited by Cure53, minimal (5KB), fastest pure JS implementation |
| @noble/secp256k1 | ^2.x    | secp256k1 utilities (already in project)      | Audited, used for public key derivation, ECDSA operations        |
| @noble/hashes    | ^1.x    | SHA-256, SHA-512 (for ed25519 sync)           | Required by @noble/ed25519 for sync methods                      |

### Supporting

| Library        | Version | Purpose                         | When to Use                                             |
| -------------- | ------- | ------------------------------- | ------------------------------------------------------- |
| @noble/curves  | ^1.x    | Full curve implementations      | Only if advanced curve operations needed beyond eciesjs |
| @noble/ciphers | ^1.x    | Pure JS AES-GCM                 | Fallback if Web Crypto unavailable (Tauri desktop)      |
| ipns           | ^10.x   | IPNS record creation/validation | Only for record marshaling format, not core crypto      |

### Alternatives Considered

| Instead of     | Could Use                    | Tradeoff                                                 |
| -------------- | ---------------------------- | -------------------------------------------------------- |
| eciesjs        | @noble/curves + custom ECIES | More control but must hand-roll ECIES protocol correctly |
| @noble/ed25519 | @libp2p/crypto               | Heavier dependency, more features not needed             |
| Web Crypto AES | @noble/ciphers               | Pure JS is slower, but works without secure context      |

**Installation:**

```bash
pnpm add eciesjs @noble/ed25519 @noble/hashes
```

Note: `@noble/secp256k1` is already in the project (used in `signatureKeyDerivation.ts`).

## Architecture Patterns

### Recommended Project Structure

```
packages/crypto/
├── src/
│   ├── index.ts              # Public exports only
│   ├── types.ts              # VaultKey, shared types
│   ├── constants.ts          # Curve parameters, sizes
│   ├── aes/
│   │   ├── index.ts          # Re-exports
│   │   ├── encrypt.ts        # AES-256-GCM encrypt
│   │   └── decrypt.ts        # AES-256-GCM decrypt
│   ├── ecies/
│   │   ├── index.ts          # Re-exports
│   │   ├── encrypt.ts        # ECIES wrap (public key)
│   │   └── decrypt.ts        # ECIES unwrap (private key)
│   ├── ed25519/
│   │   ├── index.ts          # Re-exports
│   │   ├── keygen.ts         # Ed25519 keypair generation
│   │   └── sign.ts           # Sign/verify for IPNS
│   ├── keys/
│   │   ├── index.ts          # Re-exports
│   │   ├── derive.ts         # HKDF key derivation
│   │   ├── random.ts         # Secure random generation
│   │   └── hierarchy.ts      # deriveRootKey, deriveFolderKey, etc.
│   └── utils/
│       ├── index.ts
│       ├── encoding.ts       # hex <-> bytes, base64
│       └── memory.ts         # Key clearing utilities
├── package.json
├── tsconfig.json
└── tsup.config.ts
```

### Pattern 1: VaultKey Unified Type

**What:** Single type representing user's cryptographic identity, regardless of derivation source
**When to use:** Always - callers should never know if key came from Web3Auth or external wallet

```typescript
// Source: CONTEXT.md decision
export type VaultKey = {
  publicKey: Uint8Array; // 65 bytes uncompressed secp256k1
  privateKey: Uint8Array; // 32 bytes
};

// Callers use VaultKey without knowing derivation source
async function encryptFileKey(fileKey: Uint8Array, vaultKey: VaultKey): Promise<Uint8Array> {
  return eciesEncrypt(fileKey, vaultKey.publicKey);
}
```

### Pattern 2: Async-First API

**What:** All crypto operations are async, even if underlying implementation is sync
**When to use:** Always - Web Crypto API is inherently async

```typescript
// All operations return Promise
export async function encrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array>;
export async function decrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array>;
export async function wrapKey(key: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array>;
export async function unwrapKey(wrapped: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
```

### Pattern 3: Random Key per File (No Deduplication)

**What:** Each file gets a unique random key and IV
**When to use:** Always for file encryption - security requirement

```typescript
// Source: TECHNICAL_ARCHITECTURE.md Section 3.5
export async function generateFileKey(): Promise<{ key: Uint8Array; iv: Uint8Array }> {
  return {
    key: crypto.getRandomValues(new Uint8Array(32)), // 256-bit AES key
    iv: crypto.getRandomValues(new Uint8Array(12)), // 96-bit GCM IV
  };
}
```

### Pattern 4: Error Handling - Generic Messages

**What:** Crypto errors should be generic to prevent oracle attacks
**When to use:** All decryption/verification failures

```typescript
// Good - generic error
throw new CryptoError('Decryption failed');

// Bad - reveals information
throw new CryptoError('Invalid padding');
throw new CryptoError('Authentication tag mismatch');
throw new CryptoError('Key too short');
```

### Anti-Patterns to Avoid

- **Storing keys in closures/globals:** Keys should be passed explicitly, not captured
- **Sync operations wrapping async:** Always await, never `.then()` chains
- **String keys:** Always use `Uint8Array` for binary data
- **Reusing IVs:** Generate fresh IV for every encryption operation
- **Logging key material:** Never log keys, even in debug mode

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem                  | Don't Build                       | Use Instead                | Why                                                     |
| ------------------------ | --------------------------------- | -------------------------- | ------------------------------------------------------- |
| ECIES encryption         | Custom ECDH + AES-GCM composition | `eciesjs`                  | ECIES has subtle requirements (ephemeral key, KDF, MAC) |
| Ed25519 signing          | Custom implementation             | `@noble/ed25519`           | Side-channel attacks, RFC 8032 edge cases               |
| Random number generation | `Math.random()`                   | `crypto.getRandomValues()` | CSPRNG required for cryptographic keys                  |
| Hex/bytes conversion     | String manipulation               | Library utilities          | Off-by-one errors, endianness issues                    |
| Key comparison           | `===` or loops                    | Constant-time comparison   | Timing attacks leak key information                     |

**Key insight:** Cryptographic primitives have decades of discovered edge cases. Libraries like `@noble/*` and `eciesjs` have been audited and handle these correctly.

## Common Pitfalls

### Pitfall 1: Web Crypto API Requires Secure Context

**What goes wrong:** Web Crypto API fails silently or throws in HTTP contexts
**Why it happens:** Browsers restrict `crypto.subtle` to HTTPS and localhost
**How to avoid:**

- Always serve over HTTPS in production
- Use `localhost` (not `127.0.0.1`) in development
- Add feature detection at module load
  **Warning signs:** `crypto.subtle is undefined` errors

```typescript
// Feature detection at module load
if (typeof crypto === 'undefined' || !crypto.subtle) {
  throw new Error('@cipherbox/crypto requires a secure context (HTTPS or localhost)');
}
```

### Pitfall 2: secp256k1 Not in Web Crypto API

**What goes wrong:** Trying to use `crypto.subtle.generateKey('ECDSA', { namedCurve: 'secp256k1' })`
**Why it happens:** Web Crypto only supports P-256, P-384, P-521 curves
**How to avoid:** Use `@noble/secp256k1` or `eciesjs` for all secp256k1 operations
**Warning signs:** `NotSupportedError: Named curve secp256k1 is not supported`

### Pitfall 3: IV Reuse with AES-GCM

**What goes wrong:** Catastrophic security failure - repeated IV with same key reveals plaintext
**Why it happens:** Developers reuse IV thinking it's like a salt
**How to avoid:** Generate fresh random IV for every encryption operation
**Warning signs:** Same IV appearing in multiple encrypted items

```typescript
// WRONG - reusing IV
const iv = new Uint8Array(12).fill(0);

// CORRECT - fresh random IV each time
const iv = crypto.getRandomValues(new Uint8Array(12));
```

### Pitfall 4: Memory Clearing Limitations in JavaScript

**What goes wrong:** Sensitive keys remain in memory after "clearing"
**Why it happens:** JavaScript has no guaranteed memory clearing (GC controls deallocation)
**How to avoid:**

- Fill arrays with zeros as best-effort
- Keep key lifetimes short
- Never create unnecessary copies
  **Warning signs:** Keys appearing in heap dumps

```typescript
// Best-effort clearing (not guaranteed)
export function clearKey(key: Uint8Array | null): void {
  if (key) key.fill(0);
}
```

### Pitfall 5: Ed25519 Signature Malleability

**What goes wrong:** Multiple valid signatures for same message
**Why it happens:** Ed25519 has two valid forms unless using strict verification
**How to avoid:** Use `@noble/ed25519` which follows ZIP215 by default (consensus-safe)
**Warning signs:** Signature verification inconsistencies between implementations

### Pitfall 6: ECIES Output Format Incompatibility

**What goes wrong:** ECIES from one library can't be decrypted by another
**Why it happens:** ECIES isn't a single standard - libraries differ in KDF, format, options
**How to avoid:** Use `eciesjs` consistently, document configuration, include version
**Warning signs:** "Invalid ciphertext" errors when switching libraries

## Code Examples

Verified patterns from official sources:

### AES-256-GCM Encryption with Web Crypto API

```typescript
// Source: MDN Web Crypto API documentation
export async function encryptAesGcm(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, [
    'encrypt',
  ]);

  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintext);

  // Returns ciphertext + 16-byte auth tag
  return new Uint8Array(ciphertext);
}

export async function decryptAesGcm(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, [
    'decrypt',
  ]);

  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, ciphertext);

  return new Uint8Array(plaintext);
}
```

### ECIES Key Wrapping with eciesjs

```typescript
// Source: eciesjs npm package
import { encrypt, decrypt, PrivateKey } from 'eciesjs';

export async function wrapKeyEcies(
  key: Uint8Array,
  recipientPublicKey: Uint8Array
): Promise<Uint8Array> {
  // eciesjs handles ephemeral key, ECDH, HKDF, AES-GCM internally
  return encrypt(recipientPublicKey, key);
}

export async function unwrapKeyEcies(
  wrappedKey: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  return decrypt(privateKey, wrappedKey);
}
```

### Ed25519 Key Generation and Signing

```typescript
// Source: @noble/ed25519 npm package
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';

// Enable sync methods (required for @noble/ed25519)
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export function generateEd25519Keypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = ed.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

export async function signEd25519(
  message: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  return ed.signAsync(message, privateKey);
}

export async function verifyEd25519(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  return ed.verifyAsync(signature, message, publicKey);
}
```

### HKDF Key Derivation with Web Crypto API

```typescript
// Source: MDN Web Crypto API - deriveKey
export async function deriveKey(
  inputKey: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  outputLength: number = 32
): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey('raw', inputKey, 'HKDF', false, ['deriveBits']);

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info,
    },
    keyMaterial,
    outputLength * 8 // bits
  );

  return new Uint8Array(derivedBits);
}
```

### IPNS Record Signing (Conceptual)

```typescript
// Source: IPFS IPNS spec - https://specs.ipfs.tech/ipns/ipns-record/
// Note: For full IPNS compatibility, use the `ipns` npm package for record marshaling

const IPNS_SIGNATURE_PREFIX = new Uint8Array([
  0x69,
  0x70,
  0x6e,
  0x73,
  0x2d,
  0x73,
  0x69,
  0x67,
  0x6e,
  0x61,
  0x74,
  0x75,
  0x72,
  0x65,
  0x3a, // "ipns-signature:"
]);

export async function signIpnsData(
  cborData: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  // Concatenate prefix with CBOR data
  const dataToSign = new Uint8Array(IPNS_SIGNATURE_PREFIX.length + cborData.length);
  dataToSign.set(IPNS_SIGNATURE_PREFIX, 0);
  dataToSign.set(cborData, IPNS_SIGNATURE_PREFIX.length);

  // Sign with Ed25519
  return ed.signAsync(dataToSign, privateKey);
}
```

## State of the Art

| Old Approach           | Current Approach         | When Changed | Impact                              |
| ---------------------- | ------------------------ | ------------ | ----------------------------------- |
| node-forge for Ed25519 | @noble/ed25519           | 2023         | 10x faster, audited                 |
| eccrypto for ECIES     | eciesjs                  | 2024         | Modern, @noble-based, maintained    |
| Manual ECDH + AES      | eciesjs single call      | 2024         | Less error-prone                    |
| Sync crypto operations | Async-first (Web Crypto) | 2020+        | Non-blocking, hardware acceleration |
| libsodium.js           | @noble/\* family         | 2023-2024    | Smaller bundle, pure JS, audited    |

**Deprecated/outdated:**

- `crypto-js`: Unmaintained, no TypeScript, slow
- `elliptic`: Replaced by `@noble/curves` (same author, modern rewrite)
- `secp256k1-node`: Native binding issues, use `@noble/secp256k1`
- `tweetnacl`: Good but `@noble/ed25519` is faster and more features

## Open Questions

Things that couldn't be fully resolved:

1. **IPNS Record Marshaling Format**
   - What we know: IPNS uses protobuf + DAG-CBOR format
   - What's unclear: Whether to use `ipns` npm package or implement minimal marshaling
   - Recommendation: Use `ipns` package for record creation, only implement signing ourselves

2. **Desktop (Tauri) Crypto Context**
   - What we know: Tauri uses webview which should have Web Crypto
   - What's unclear: Whether all Web Crypto operations work identically
   - Recommendation: Test in Tauri early, have `@noble/ciphers` fallback ready

3. **TEE Public Key Format for ECIES**
   - What we know: TEE public keys are secp256k1, used for IPNS key wrapping
   - What's unclear: Exact format (compressed vs uncompressed) the TEE expects
   - Recommendation: Default to uncompressed (65 bytes), configurable

## Sources

### Primary (HIGH confidence)

- [MDN Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) - AES-GCM, HKDF documentation
- [MDN SubtleCrypto.deriveKey](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey) - HKDF with ECDH examples
- [noble-curves GitHub](https://github.com/paulmillr/noble-curves) - secp256k1 API, audit status
- [noble-ed25519 GitHub](https://github.com/paulmillr/noble-ed25519) - Ed25519 API, usage examples
- [eciesjs GitHub](https://github.com/ecies/js) - ECIES API, configuration options
- [eciesjs npm](https://www.npmjs.com/package/eciesjs) - Version, browser compatibility
- [IPNS Spec](https://specs.ipfs.tech/ipns/ipns-record/) - IPNS record structure, signature format

### Secondary (MEDIUM confidence)

- [NIST CAVP Block Cipher Modes](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes) - AES-GCM test vectors reference
- [@libp2p/crypto GitHub](https://github.com/libp2p/js-libp2p-crypto) - Ed25519 key marshaling format
- [W3C WebCrypto Issue #82](https://github.com/w3c/webcrypto/issues/82) - secp256k1 not in Web Crypto (confirmed limitation)

### Tertiary (LOW confidence)

- WebSearch results for library comparisons - used to identify current best practices
- GitHub issue discussions - used to understand edge cases and pitfalls

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH - All libraries audited, widely used, documented
- Architecture: HIGH - Follows project CONTEXT.md decisions, proven patterns
- Pitfalls: HIGH - Well-documented issues in crypto community

**Research date:** 2026-01-20
**Valid until:** 2026-03-20 (60 days - crypto libraries are stable)

---

_Phase: 03-core-encryption_
_Research completed: 2026-01-20_
