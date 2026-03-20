/**
 * SDK Integration Test — tests real API operations (requires running API).
 * Run: pnpm --filter @cipherbox/sdk vitest run src/__tests__/integration.test.ts --no-coverage
 */
import { describe, it, expect } from 'vitest';
import { CipherBoxClient } from '../client';
import { setApiClientConfig } from '@cipherbox/api-client';
import {
  initializeVault,
  encryptVaultKeys,
  deriveIpnsName,
  hexToBytes,
  bytesToHex,
} from '@cipherbox/crypto';

const API = 'http://localhost:3000';
const SECRET = 'e2e-test-secret-do-not-use-in-production';

const describeIf = process.env.CI ? describe.skip : describe;

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
          encryptedRootFolderKey: bytesToHex(encrypted.encryptedRootFolderKey),
          encryptedRootIpnsPrivateKey: bytesToHex(encrypted.encryptedIpnsPrivateKey),
          rootIpnsName,
        }),
      });
      expect(initRes.ok).toBe(true);

      setApiClientConfig({ baseUrl: API, getAccessToken: async () => accessToken });

      const client = new CipherBoxClient({
        apiUrl: API,
        getAccessToken: async () => accessToken,
        vaultKeypair: { publicKey, privateKey },
        rootIpnsName,
        rootFolderKey: vault.rootFolderKey,
      });
      client.registerFolder(rootIpnsName, vault.rootFolderKey, vault.rootIpnsKeypair, [], 0n);

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
        const root = (client as any).folderTree.get(rootIpnsName);
        const fileChild = root?.children.find(
          (c: any) => c.type === 'file' && c.name === 'test.txt'
        );
        expect(fileChild).toBeTruthy();

        const downloaded = await client.downloadFromIpns(
          fileChild.fileMetaIpnsName,
          vault.rootFolderKey
        );
        const downloadedText = new TextDecoder().decode(downloaded);
        expect(downloadedText).toBe(originalContent);
        console.log('  ✓ Download via downloadFromIpns (content verified)');

        // 4. Rename file
        await client.renameItem(rootIpnsName, fileChild.id, 'renamed.txt');
        const afterRename = (client as any).folderTree.get(rootIpnsName);
        expect(afterRename.children.find((c: any) => c.name === 'renamed.txt')).toBeTruthy();
        console.log('  ✓ Rename file');

        // 5. Rename folder
        await client.renameItem(rootIpnsName, folder.id, 'RenamedFolder');
        const afterFolderRename = (client as any).folderTree.get(rootIpnsName);
        expect(
          afterFolderRename.children.find((c: any) => c.name === 'RenamedFolder')
        ).toBeTruthy();
        console.log('  ✓ Rename folder');

        // 6. Delete file
        const deleteResult = await client.deleteItem(rootIpnsName, fileChild.id);
        expect(deleteResult.removedItem.id).toBe(fileChild.id);
        console.log('  ✓ Delete file');

        // 7. Delete folder
        const folderDelete = await client.deleteItem(rootIpnsName, folder.id);
        expect(folderDelete.removedItem.id).toBe(folder.id);
        console.log('  ✓ Delete folder');

        // Verify root is empty
        const finalRoot = (client as any).folderTree.get(rootIpnsName);
        expect(finalRoot.children.length).toBe(0);
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
          encryptedRootFolderKey: bytesToHex(encrypted.encryptedRootFolderKey),
          encryptedRootIpnsPrivateKey: bytesToHex(encrypted.encryptedIpnsPrivateKey),
          rootIpnsName,
        }),
      });
      expect(initRes.ok).toBe(true);

      setApiClientConfig({ baseUrl: API, getAccessToken: async () => accessToken });

      const client = new CipherBoxClient({
        apiUrl: API,
        getAccessToken: async () => accessToken,
        vaultKeypair: { publicKey, privateKey },
        rootIpnsName,
        rootFolderKey: vault.rootFolderKey,
      });
      client.registerFolder(rootIpnsName, vault.rootFolderKey, vault.rootIpnsKeypair, [], 0n);

      try {
        // 1. loadBin on fresh account — should return empty state (not null)
        const binState = await client.loadBin();
        expect(binState).toBeTruthy();
        expect(binState.entries).toEqual([]);
        expect(binState.sequenceNumber).toBe(0);
        console.log('  ✓ loadBin on fresh account returns empty state');

        // 2. Upload a file
        const fileData = new TextEncoder().encode('bin test ' + Date.now());
        await client.uploadFile(rootIpnsName, fileData, 'bin-test.txt', 'text/plain');
        const root = (client as any).folderTree.get(rootIpnsName);
        const fileChild = root.children.find((c: any) => c.name === 'bin-test.txt');
        expect(fileChild).toBeTruthy();
        console.log('  ✓ Uploaded file for bin test');

        // 3. deleteToBin — should NOT throw "Bin not loaded"
        await client.deleteToBin(rootIpnsName, fileChild.id, 'My Vault');
        console.log('  ✓ deleteToBin succeeded (no "Bin not loaded" error)');

        // 4. Verify bin state has the entry
        const updatedBin = (client as any).binState;
        expect(updatedBin.entries.length).toBe(1);
        expect(updatedBin.entries[0].name).toBe('bin-test.txt');
        expect(updatedBin.entries[0].itemType).toBe('file');
        console.log('  ✓ Bin contains deleted file entry');

        // 5. Verify file removed from root
        const rootAfterDelete = (client as any).folderTree.get(rootIpnsName);
        expect(rootAfterDelete.children.length).toBe(0);
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
});
