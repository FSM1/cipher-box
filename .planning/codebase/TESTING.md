# Testing Patterns

**Analysis Date:** 2026-01-19

## Test Framework

**Runner:**
- Not configured (no test framework detected)
- No `jest.config.js`, `vitest.config.js`, or similar found
- No test scripts in `poc/package.json`

**Assertion Library:**
- Not applicable

**Run Commands:**
- Not applicable (no tests present)

## Test File Organization

**Location:**
- No test files detected in codebase
- Expected pattern would be co-located or in `__tests__/` directory

**Naming:**
- Not applicable (no test files)
- Standard pattern would be `*.test.ts` or `*.spec.ts`

**Structure:**
- Not applicable

## Test Structure

**Suite Organization:**
Not applicable - no tests present

**Current Testing Approach:**
The codebase uses manual verification through a PoC harness (`poc/src/index.ts`) that:
1. Executes a complete workflow (create folders, upload files, modify, move, delete)
2. Verifies operations through inline assertions and console output
3. Reports success/failure via exit code

Example verification pattern from PoC:
```typescript
await downloadAndVerifyFile(ctx, docsFolder, fileName, fileContent, docsAfterUpload.cid);
console.log("File verified after upload");
```

## Mocking

**Framework:**
Not configured

**Patterns:**
- No mocking observed
- PoC uses real IPFS node connection
- Integration test approach: tests against actual services

## Fixtures and Factories

**Test Data:**
Generated programmatically in PoC harness:
```typescript
const fileName = "hello.txt";
const fileContent = utf8ToBytes("Hello, CipherBox PoC!");
const fileKey = randomBytes(32);
```

**Synthetic Data Generation:**
```typescript
const addSyntheticChildren = async (ctx: HarnessContext, folder: FolderState): Promise<void> => {
    const count = ctx.stressChildrenCount;
    if (count <= 0) return;

    for (let i = 0; i < count; i += 1) {
        const name = `stress-file-${String(i + 1).padStart(5, "0")}.txt`;
        // ... create synthetic entries
    }
};
```

**Location:**
- Inline in `poc/src/index.ts` (no separate fixtures directory)

## Coverage

**Requirements:**
None enforced

**View Coverage:**
Not applicable

## Test Types

**Unit Tests:**
- Not present
- Would test individual crypto functions (`aesGcmEncrypt`, `eciesEncrypt`, etc.)

**Integration Tests:**
- PoC harness serves as integration test
- Run via: `npm start` in `poc/` directory
- Tests full workflow: auth → folder creation → file operations → cleanup
- Validates against live IPFS node

**E2E Tests:**
- Not applicable (no UI to test)

## Testing Recommendations

Based on codebase analysis, recommended test structure:

**Unit Tests Needed:**
- Encryption/decryption functions (`aesGcmEncrypt`, `aesGcmDecrypt`)
- Key wrapping functions (`eciesEncryptBytes`, `eciesDecryptBytes`)
- Data conversion utilities (`hexToBytes`, `bytesToUtf8`, etc.)
- Metadata encryption/decryption (`encryptMetadata`, `decryptMetadata`)
- Name encryption/decryption (`encryptName`, `decryptName`)

**Integration Tests Needed:**
- IPFS operations (add, cat, pin)
- IPNS operations (publish, resolve)
- Pinata API interactions
- State persistence

**Test Framework Recommendation:**
- Vitest (modern, fast, TypeScript-first)
- Or Jest with ts-jest
- Both compatible with existing ESM setup (`"type": "module"` in package.json)

**Example Test Structure:**
```typescript
// crypto.test.ts
import { describe, it, expect } from 'vitest';
import { aesGcmEncrypt, aesGcmDecrypt } from './index';

describe('AES-GCM encryption', () => {
    it('encrypts and decrypts data correctly', () => {
        const key = randomBytes(32);
        const plaintext = utf8ToBytes('test data');
        const { ciphertext, iv } = aesGcmEncrypt(plaintext, key);
        const decrypted = aesGcmDecrypt(ciphertext, key, iv);
        expect(bytesToUtf8(decrypted)).toBe('test data');
    });
});
```

## Verification Patterns

**Current Approach:**
Manual verification in PoC harness:

1. **File Verification:**
```typescript
const downloadAndVerifyFile = async (
    ctx: HarnessContext,
    folder: FolderState,
    expectedName: string,
    expectedContent: Uint8Array,
    expectedMetadataCid?: string
): Promise<void> => {
    // ... fetch and decrypt file
    if (bytesToHex(plaintext) !== bytesToHex(expectedContent)) {
        throw new Error(`File content mismatch for ${expectedName}`);
    }
};
```

2. **IPNS Resolution Verification:**
```typescript
const waitForIpns = async (ctx: HarnessContext, ipnsName: string, expectedCid: string): Promise<number> => {
    // Poll until IPNS resolves to expected CID
    const resolvedCid = await resolveIpnsToCid(ctx, ipnsName, { nocache: true });
    if (resolvedCid === expectedCid) {
        return Date.now() - start;
    }
    // ... timeout handling
};
```

3. **Tree Visualization:**
```typescript
const logFolderTree = async (ctx: HarnessContext, root: FolderState, label: string): Promise<void> => {
    console.log(`\n--- File tree (${label}) ---`);
    const lines = await buildFolderTree(ctx, root);
    console.log(lines.join("\n"));
};
```

## Common Patterns

**Async Testing:**
All operations are async:
```typescript
const main = async (): Promise<void> => {
    // ... async workflow
};

main().catch((error) => {
    console.error("PoC harness failed:", error);
    process.exit(1);
});
```

**Error Testing:**
Error handling through try-catch with console warnings:
```typescript
try {
    await ctx.ipfs.pin.rm(cid);
} catch (error) {
    console.warn(`Pin rm skipped for ${cid}: ${(error as Error).message}`);
}
```

**Performance Testing:**
Timing measurements built into PoC:
```typescript
const waitForIpns = async (...): Promise<number> => {
    const start = Date.now();
    // ... operation
    return Date.now() - start;
};

const { cid, delayMs } = await publishFolderMetadata(ctx, rootFolder);
console.log(`Root published CID: ${cid} (IPNS delay ${delayMs}ms)`);
```

## Test Execution Environment

**Requirements:**
- Running IPFS node (local or remote)
- IPFS API endpoint configured via `IPFS_API_URL` env var
- ECDSA private key in `ECDSA_PRIVATE_KEY` env var
- Optional: Pinata API keys for pinning integration

**Configuration:**
Environment variables in `.env` file:
```bash
ECDSA_PRIVATE_KEY=<hex>
IPFS_API_URL=http://127.0.0.1:5001
IPNS_POLL_INTERVAL_MS=1500
IPNS_POLL_TIMEOUT_MS=120000
STRESS_CHILDREN_COUNT=0
STRESS_CHILD_TYPE=file
PINATA_ENABLED=false
```

**State Management:**
- Test state written to `state/` directory
- `state.json` contains root folder keys and IPNS names
- State preserved between runs for debugging

---

*Testing analysis: 2026-01-19*
