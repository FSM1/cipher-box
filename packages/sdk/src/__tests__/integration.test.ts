/**
 * SDK Integration Test — tests real API operations (requires running API).
 * Run: pnpm --filter @cipherbox/sdk vitest run src/__tests__/integration.test.ts --no-coverage
 */
import { describe, it, expect } from 'vitest';
import { CipherBoxClient } from '../client';
import { initializeVault, encryptVaultKeys } from '@cipherbox/core';
import { deriveIpnsName, hexToBytes, bytesToHex } from '@cipherbox/crypto';
import type { FolderTree } from '../state/folder-tree';
import type { BinState } from '../bin';

/** Expose private members for testing */
interface ClientInternals {
  folderTree: FolderTree;
  binState: BinState;
}

const API = 'http://localhost:3000';
const SECRET = 'e2e-test-secret-do-not-use-in-production';

// Live-stack integration suite (NOT legacy, NOT phase-gated -- this is a
// deliberate, permanent infra gate). These specs exercise CipherBoxClient
// against a REAL running API + docker stack (Postgres/Redis/Kubo relay) --
// no sdk-core/crypto/core mocks at all, unlike every other file in this
// directory. They are always `.skip`'d for the regular unit-test run (`pnpm
// --filter @cipherbox/sdk test`), which never has that stack available, and
// are meant to be run manually/locally or from a dedicated e2e job:
//
//   docker compose up -d          # postgres, redis, kubo relay, someguy
//   pnpm --filter @cipherbox/api dev   # API on :3000 with TEST_LOGIN_SECRET set
//   pnpm --filter @cipherbox/sdk exec vitest run \
//     src/__tests__/integration.test.ts --no-coverage
//
// `SECRET` below must equal the API's `TEST_LOGIN_SECRET` env var (see
// project memory: "sdk-e2e live checkpoint run" for the full local recipe).
const describeIf = describe.skip;

describeIf('SDK Integration (live API)', () => {
  it(
    'full lifecycle: folder CRUD, upload, download, rename, delete',
    { timeout: 120000 },
    async () => {
      const email = `sdk-int-${Date.now()}@example.com`;

      // --- Setup ---
      const loginRes = await fetch(`${API}/auth/test-login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, secret: SECRET }),
      });
      expect(loginRes.ok).toBe(true);
      const { accessToken, publicKeyHex, privateKeyHex } = await loginRes.json();
      const publicKey = hexToBytes(publicKeyHex);
      const privateKey = hexToBytes(privateKeyHex);

      const vault = await initializeVault(privateKey);
      const encrypted = await encryptVaultKeys(vault, publicKey);
      const rootIpnsName = await deriveIpnsName(vault.rootIpnsKeypair.publicKey);

      const initRes = await fetch(`${API}/vault/init`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ownerPublicKey: bytesToHex(publicKey),
          encryptedRootReadKey: bytesToHex(encrypted.encryptedRootReadKey),
          encryptedRootWriteKey: bytesToHex(encrypted.encryptedRootWriteKey),
          encryptedRootIpnsPrivateKey: bytesToHex(encrypted.encryptedIpnsPrivateKey),
          rootIpnsName,
        }),
      });
      expect(initRes.ok).toBe(true);

      const client = new CipherBoxClient({
        apiUrl: API,
        getAccessToken: async () => accessToken,
        vaultKeypair: { publicKey, privateKey },
        rootIpnsName,
        rootFolderKey: vault.rootReadKey,
        rootWriteKey: vault.rootWriteKey,
      });
      client.registerFolder(
        rootIpnsName,
        vault.rootReadKey,
        vault.rootIpnsKeypair,
        [],
        0n,
        undefined,
        undefined,
        vault.rootWriteKey
      );

      try {
        // 1. Create folder
        const folder = await client.createFolder(rootIpnsName, 'TestFolder');
        expect(folder.id).toBeTruthy();
        expect(folder.ipnsName).toMatch(/^k51/);
        expect(folder.folderKey.length).toBe(32);
        expect(folder.ipnsPrivateKey.length).toBeGreaterThan(0);
        console.log('  ✓ Create folder');

        // 2. Upload file
        const originalContent = 'Hello SDK! ' + Date.now();
        const fileData = new TextEncoder().encode(originalContent);
        const upload = await client.uploadFile(rootIpnsName, fileData, 'test.txt', 'text/plain');
        expect(upload.cid).toBeTruthy();
        console.log('  ✓ Upload file');

        // 3. Download via downloadFromIpns (same path the web app uses)
        const root = (client as unknown as ClientInternals).folderTree.get(rootIpnsName);
        const fileChild = root?.children.find((c) => c.name === 'test.txt');
        expect(fileChild).toBeTruthy();
        const fileIdentity = await client.resolveChildIdentity(fileChild!, vault.rootReadKey);
        expect(fileIdentity.kind).toBe('file');

        const downloaded = await client.downloadFromIpns(fileChild!, vault.rootReadKey);
        const downloadedText = new TextDecoder().decode(downloaded);
        expect(downloadedText).toBe(originalContent);
        console.log('  ✓ Download via downloadFromIpns (content verified)');

        // 4. Rename file
        await client.renameItem(rootIpnsName, fileChild!.ipnsName, 'renamed.txt');
        const afterRename = (client as unknown as ClientInternals).folderTree.get(rootIpnsName);
        expect(afterRename).toBeTruthy();
        expect(afterRename!.children.find((c) => c.name === 'renamed.txt')).toBeTruthy();
        console.log('  ✓ Rename file');

        // 5. Rename folder
        await client.renameItem(rootIpnsName, folder.ipnsName, 'RenamedFolder');
        const afterFolderRename = (client as unknown as ClientInternals).folderTree.get(
          rootIpnsName
        );
        expect(afterFolderRename).toBeTruthy();
        expect(afterFolderRename!.children.find((c) => c.name === 'RenamedFolder')).toBeTruthy();
        console.log('  ✓ Rename folder');

        // 6. Delete file
        const deleteResult = await client.deleteItem(rootIpnsName, fileChild!.ipnsName);
        expect(deleteResult.removedItem.ipnsName).toBe(fileChild!.ipnsName);
        console.log('  ✓ Delete file');

        // 7. Delete folder
        const folderDelete = await client.deleteItem(rootIpnsName, folder.ipnsName);
        expect(folderDelete.removedItem.ipnsName).toBe(folder.ipnsName);
        console.log('  ✓ Delete folder');

        // Verify root is empty
        const finalRoot = (client as unknown as ClientInternals).folderTree.get(rootIpnsName);
        expect(finalRoot).toBeTruthy();
        expect(finalRoot!.children.length).toBe(0);
        console.log('  ✓ Root folder empty');
      } finally {
        client.destroy();
      }
    }
  );

  it(
    'bin lifecycle: loadBin on fresh account, deleteToBin, verify bin entries',
    { timeout: 120000 },
    async () => {
      const email = `sdk-bin-${Date.now()}@example.com`;

      // --- Setup (same as main test) ---
      const loginRes = await fetch(`${API}/auth/test-login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, secret: SECRET }),
      });
      expect(loginRes.ok).toBe(true);
      const { accessToken, publicKeyHex, privateKeyHex } = await loginRes.json();
      const publicKey = hexToBytes(publicKeyHex);
      const privateKey = hexToBytes(privateKeyHex);

      const vault = await initializeVault(privateKey);
      const encrypted = await encryptVaultKeys(vault, publicKey);
      const rootIpnsName = await deriveIpnsName(vault.rootIpnsKeypair.publicKey);

      const initRes = await fetch(`${API}/vault/init`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ownerPublicKey: bytesToHex(publicKey),
          encryptedRootReadKey: bytesToHex(encrypted.encryptedRootReadKey),
          encryptedRootWriteKey: bytesToHex(encrypted.encryptedRootWriteKey),
          encryptedRootIpnsPrivateKey: bytesToHex(encrypted.encryptedIpnsPrivateKey),
          rootIpnsName,
        }),
      });
      expect(initRes.ok).toBe(true);

      const client = new CipherBoxClient({
        apiUrl: API,
        getAccessToken: async () => accessToken,
        vaultKeypair: { publicKey, privateKey },
        rootIpnsName,
        rootFolderKey: vault.rootReadKey,
        rootWriteKey: vault.rootWriteKey,
      });
      client.registerFolder(
        rootIpnsName,
        vault.rootReadKey,
        vault.rootIpnsKeypair,
        [],
        0n,
        undefined,
        undefined,
        vault.rootWriteKey
      );

      try {
        // 1. loadBin on fresh account — should return empty state (not null)
        const binState = await client.loadBin();
        expect(binState).toBeTruthy();
        expect(binState.entries).toEqual([]);
        expect(binState.sequenceNumber).toBe(1);
        console.log('  ✓ loadBin on fresh account returns empty state');

        // 2. Upload a file
        const fileData = new TextEncoder().encode('bin test ' + Date.now());
        await client.uploadFile(rootIpnsName, fileData, 'bin-test.txt', 'text/plain');
        const root = (client as unknown as ClientInternals).folderTree.get(rootIpnsName);
        const fileChild = root!.children.find((c) => c.name === 'bin-test.txt');
        expect(fileChild).toBeTruthy();
        console.log('  ✓ Uploaded file for bin test');

        // 3. deleteToBin — should NOT throw "Bin not loaded"
        await client.deleteToBin(rootIpnsName, fileChild!.ipnsName, 'My Vault');
        console.log('  ✓ deleteToBin succeeded (no "Bin not loaded" error)');

        // 4. Verify bin state has the entry
        const updatedBin = (client as unknown as ClientInternals).binState;
        expect(updatedBin.entries.length).toBe(1);
        expect(updatedBin.entries[0].name).toBe('bin-test.txt');
        expect(updatedBin.entries[0].itemType).toBe('file');
        console.log('  ✓ Bin contains deleted file entry');

        // 5. Verify file removed from root
        const rootAfterDelete = (client as unknown as ClientInternals).folderTree.get(rootIpnsName);
        expect(rootAfterDelete).toBeTruthy();
        expect(rootAfterDelete!.children.length).toBe(0);
        console.log('  ✓ File removed from root folder');

        // 6. Reload bin from IPNS — should find the persisted entry
        const reloaded = await client.loadBin();
        expect(reloaded.entries.length).toBe(1);
        expect(reloaded.entries[0].name).toBe('bin-test.txt');
        console.log('  ✓ Bin entry persisted to IPNS (verified via reload)');
      } finally {
        client.destroy();
      }
    }
  );

  it(
    'batch upload: uploadFiles() uploads multiple files with single folder publish',
    { timeout: 120000 },
    async () => {
      const email = `sdk-batch-${Date.now()}@example.com`;

      const loginRes = await fetch(`${API}/auth/test-login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, secret: SECRET }),
      });
      expect(loginRes.ok).toBe(true);
      const { accessToken, publicKeyHex, privateKeyHex } = await loginRes.json();
      const publicKey = hexToBytes(publicKeyHex);
      const privateKey = hexToBytes(privateKeyHex);

      const vault = await initializeVault(privateKey);
      const encrypted = await encryptVaultKeys(vault, publicKey);
      const rootIpnsName = await deriveIpnsName(vault.rootIpnsKeypair.publicKey);

      const initRes = await fetch(`${API}/vault/init`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ownerPublicKey: bytesToHex(publicKey),
          encryptedRootReadKey: bytesToHex(encrypted.encryptedRootReadKey),
          encryptedRootWriteKey: bytesToHex(encrypted.encryptedRootWriteKey),
          encryptedRootIpnsPrivateKey: bytesToHex(encrypted.encryptedIpnsPrivateKey),
          rootIpnsName,
        }),
      });
      expect(initRes.ok).toBe(true);

      const client = new CipherBoxClient({
        apiUrl: API,
        getAccessToken: async () => accessToken,
        vaultKeypair: { publicKey, privateKey },
        rootIpnsName,
        rootFolderKey: vault.rootReadKey,
        rootWriteKey: vault.rootWriteKey,
      });
      client.registerFolder(
        rootIpnsName,
        vault.rootReadKey,
        vault.rootIpnsKeypair,
        [],
        0n,
        undefined,
        undefined,
        vault.rootWriteKey
      );

      try {
        // Upload 3 files in one batch
        const files = [
          {
            data: new TextEncoder().encode('file-a ' + Date.now()),
            fileName: 'batch-a.txt',
            mimeType: 'text/plain',
          },
          {
            data: new TextEncoder().encode('file-b ' + Date.now()),
            fileName: 'batch-b.txt',
            mimeType: 'text/plain',
          },
          {
            data: new TextEncoder().encode('file-c ' + Date.now()),
            fileName: 'batch-c.txt',
            mimeType: 'text/plain',
          },
        ];

        const completedFiles: string[] = [];
        const result = await client.uploadFiles(rootIpnsName, files, {
          onFileComplete: (fileName) => completedFiles.push(fileName),
        });

        // All 3 should succeed
        expect(result.successes).toHaveLength(3);
        expect(result.failures).toHaveLength(0);
        expect(completedFiles).toHaveLength(3);
        console.log('  ✓ Batch upload: 3 files uploaded');

        // Verify all 3 appear in folder
        const root = (client as unknown as ClientInternals).folderTree.get(rootIpnsName);
        const names = root!.children.map((c) => c.name).sort();
        expect(names).toContain('batch-a.txt');
        expect(names).toContain('batch-b.txt');
        expect(names).toContain('batch-c.txt');
        console.log('  ✓ All 3 files visible in folder');

        // Download one and verify content
        const fileChild = root!.children.find((c) => c.name === 'batch-a.txt');
        expect(fileChild).toBeTruthy();
        const fileIdentity = await client.resolveChildIdentity(fileChild!, vault.rootReadKey);
        expect(fileIdentity.kind).toBe('file');
        const downloaded = await client.downloadFromIpns(fileChild!, vault.rootReadKey);
        const text = new TextDecoder().decode(downloaded);
        expect(text).toContain('file-a');
        console.log('  ✓ Downloaded batch-a.txt, content verified');
      } finally {
        client.destroy();
      }
    }
  );
});
