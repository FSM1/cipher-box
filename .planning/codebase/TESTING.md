# Testing Patterns

**Analysis Date:** 2026-01-20

## Test Framework

**Runner:**
- Not configured - no test framework installed

**Assertion Library:**
- Not configured

**Run Commands:**
```bash
# No test commands available
# package.json does not include test scripts
```

## Current State

**Status:** No automated testing infrastructure exists in this codebase.

The project is in preliminary R&D/POC phase. The only "testing" is:
1. Manual execution of the POC harness (`npm start`)
2. Runtime verification within the POC code itself

## POC Verification Pattern

The POC (`00-Preliminary-R&D/poc/src/index.ts`) uses inline verification:

```typescript
// Verification is built into the workflow
const downloadAndVerifyFile = async (
    ctx: HarnessContext,
    folder: FolderState,
    expectedName: string,
    expectedContent: Uint8Array,
    expectedMetadataCid?: string
): Promise<void> => {
    // ... fetch and decrypt file ...

    if (bytesToHex(plaintext) !== bytesToHex(expectedContent)) {
        throw new Error(`File content mismatch for ${expectedName}`);
    }
};

// Called after each operation
await downloadAndVerifyFile(ctx, docsFolder, fileName, fileContent, docsAfterUpload.cid);
console.log("File verified after upload");
```

## Recommended Testing Setup (for future implementation)

Based on project patterns and TypeScript configuration:

**Recommended Framework:**
- Vitest (compatible with ES2022 modules and TypeScript)

**Recommended Configuration:**
```typescript
// vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
  },
});
```

**Recommended package.json scripts:**
```json
{
  "scripts": {
    "test": "vitest",
    "test:watch": "vitest --watch",
    "test:coverage": "vitest --coverage"
  }
}
```

## Test File Organization

**Recommended Location:**
- Co-located: `src/crypto.test.ts` alongside `src/crypto.ts`
- Or separate: `tests/` directory at project root

**Recommended Naming:**
- `*.test.ts` for test files

## Recommended Test Structure

**Suite Organization:**
```typescript
import { describe, it, expect } from 'vitest';
import { hexToBytes, bytesToHex, aesGcmEncrypt, aesGcmDecrypt } from './crypto';

describe('hexToBytes', () => {
  it('converts hex string to Uint8Array', () => {
    const hex = 'deadbeef';
    const bytes = hexToBytes(hex);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(4);
  });

  it('handles 0x prefix', () => {
    const hex = '0xdeadbeef';
    const bytes = hexToBytes(hex);
    expect(bytesToHex(bytes)).toBe('deadbeef');
  });
});

describe('AES-GCM encryption', () => {
  it('encrypts and decrypts data', () => {
    const key = new Uint8Array(32).fill(0x42);
    const plaintext = new Uint8Array([1, 2, 3, 4]);

    const { ciphertext, iv } = aesGcmEncrypt(plaintext, key);
    const decrypted = aesGcmDecrypt(ciphertext, key, iv);

    expect(decrypted).toEqual(plaintext);
  });
});
```

## Recommended Mocking

**For IPFS operations:**
```typescript
import { vi } from 'vitest';

const mockIpfs = {
  add: vi.fn().mockResolvedValue({ cid: { toString: () => 'QmTest123' } }),
  cat: vi.fn().mockImplementation(async function* () {
    yield new Uint8Array([1, 2, 3]);
  }),
  pin: {
    add: vi.fn().mockResolvedValue(undefined),
    rm: vi.fn().mockResolvedValue(undefined),
  },
  name: {
    publish: vi.fn().mockResolvedValue(undefined),
    resolve: vi.fn().mockImplementation(async function* () {
      yield '/ipfs/QmTest123';
    }),
  },
  key: {
    gen: vi.fn().mockResolvedValue({ id: 'k51test', name: 'test-key' }),
    rm: vi.fn().mockResolvedValue(undefined),
  },
};
```

**What to Mock:**
- IPFS client operations (network calls)
- Pinata API calls
- File system operations in unit tests

**What NOT to Mock:**
- Cryptographic functions (test real encryption/decryption)
- Data conversion utilities (hexToBytes, bytesToHex)

## Test Data / Fixtures

**Recommended Pattern:**
```typescript
// tests/fixtures/keys.ts
export const testPrivateKey = new Uint8Array(32).fill(0x42);
export const testPublicKey = getPublicKey(testPrivateKey, false);

// tests/fixtures/metadata.ts
export const emptyFolderMetadata: FolderMetadata = {
  children: [],
  metadata: { created: 1705298400000, modified: 1705298400000 },
};
```

## Coverage

**Requirements:** None enforced (no test infrastructure)

**Recommended targets:**
- 80% line coverage for crypto utilities
- 100% coverage for data conversion functions
- Integration tests for end-to-end file operations

## Test Types (Recommended)

**Unit Tests:**
- Crypto functions: `aesGcmEncrypt`, `aesGcmDecrypt`, `eciesEncryptBytes`
- Data utilities: `hexToBytes`, `bytesToHex`, `encryptName`, `decryptName`
- Metadata handling: `encryptMetadata`, `decryptMetadata`

**Integration Tests:**
- Full upload/download cycle with mocked IPFS
- Folder creation and subfolder attachment
- File move between folders

**E2E Tests:**
- Not applicable for current POC
- Would require running IPFS node

## Priority Test Areas

Based on project criticality:

1. **Cryptographic correctness** (highest priority)
   - Encryption/decryption roundtrips
   - Key derivation
   - ECIES key wrapping

2. **Metadata integrity**
   - Encrypt/decrypt metadata
   - Entry addition/removal

3. **Binary data handling**
   - Hex/bytes conversions
   - UTF-8 encoding

---

*Testing analysis: 2026-01-20*
