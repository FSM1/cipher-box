/**
 * rename-folder.mjs -- Rename a folder in the vault via the SDK.
 *
 * Authenticates via test-login, finds the target folder in the root
 * folder metadata, renames it using renameInFolder, and republishes
 * the root folder metadata so other clients (e.g. FUSE mount) detect
 * the change.
 *
 * Usage:
 *   TEST_SECRET=<secret> node rename-folder.mjs \
 *     --api-url http://localhost:3000 \
 *     --email dev-key@cipherbox.local \
 *     --folder-name "OldName" \
 *     --new-name "NewName"
 */

import { createAxiosInstance } from '../../api-client/dist/index.mjs';
import {
  loadVaultKeyBlob,
  loadFolderMetadata,
  renameInFolder,
  updateFolderMetadataAndPublish,
} from '../dist/index.mjs';
import {
  deriveVaultIpnsKeypair,
  clearBytes,
} from '../../crypto/dist/index.mjs';

function parseArgs(argv) {
  const values = new Map();

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) {
      throw new Error(`Unexpected argument: ${token}`);
    }

    const key = token.slice(2);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) {
      throw new Error(`Missing value for --${key}`);
    }

    values.set(key, value);
    i += 1;
  }

  if (values.has('secret')) {
    throw new Error('Do not pass --secret on CLI. Set TEST_SECRET in environment.');
  }

  const apiUrl = values.get('api-url');
  const secret = process.env.TEST_SECRET;
  const email = values.get('email');
  const folderName = values.get('folder-name');
  const newName = values.get('new-name');

  if (!apiUrl || !email || !folderName || !secret || !newName) {
    throw new Error(
      'Usage: rename-folder.mjs --api-url <url> --email <email> --folder-name <name> --new-name <name> (requires TEST_SECRET env var)'
    );
  }

  return { apiUrl, secret, email, folderName, newName };
}

async function authenticate(apiUrl, email, secret) {
  const response = await fetch(`${apiUrl}/auth/test-login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, secret }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`test-login failed (${response.status}): ${body}`);
  }

  const payload = await response.json();

  if (!payload.accessToken || !payload.privateKeyHex || !payload.publicKeyHex) {
    throw new Error('test-login response missing accessToken, privateKeyHex, or publicKeyHex');
  }

  return payload;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const auth = await authenticate(args.apiUrl, args.email, args.secret);
  const accessToken = auth.accessToken;
  const userPrivateKey = Uint8Array.from(Buffer.from(auth.privateKeyHex, 'hex'));

  const axiosInstance = createAxiosInstance({
    baseUrl: args.apiUrl,
    getAccessToken: async () => accessToken,
  });

  const ctx = {
    apiUrl: args.apiUrl,
    getAccessToken: async () => accessToken,
    axiosInstance,
  };

  // 1. Load vault key blob to get rootFolderKey
  const vaultKeyBlob = await loadVaultKeyBlob({ userPrivateKey, ctx });
  if (!vaultKeyBlob) {
    throw new Error('Vault key blob not found');
  }

  // 2. Get vault info for rootIpnsName
  const vaultResponse = await axiosInstance.get('/vault');
  const rootIpnsName = vaultResponse.data.rootIpnsName;
  if (!rootIpnsName) {
    throw new Error('Vault response missing rootIpnsName');
  }

  // 3. Load root folder metadata
  const folder = await loadFolderMetadata({
    ipnsName: rootIpnsName,
    folderKey: vaultKeyBlob.rootFolderKey,
    ctx,
  });
  if (!folder) {
    throw new Error(`Root folder metadata not found for ${rootIpnsName}`);
  }

  // 4. Find the target folder entry by name
  const folderEntry = folder.metadata.children.find(
    (child) => child.type === 'folder' && child.name === args.folderName
  );
  if (!folderEntry) {
    throw new Error(`Folder not found: ${args.folderName}`);
  }

  // 5. Rename the folder in metadata
  const { updatedChildren } = renameInFolder({
    children: folder.metadata.children,
    childId: folderEntry.id,
    newName: args.newName,
  });

  // 6. Derive root folder IPNS keypair for republishing
  const rootIpnsKeypair = await deriveVaultIpnsKeypair(userPrivateKey);

  // 7. Republish folder metadata with the renamed entry
  const { newSequenceNumber } = await updateFolderMetadataAndPublish({
    children: updatedChildren,
    folderKey: vaultKeyBlob.rootFolderKey,
    ipnsPrivateKey: rootIpnsKeypair.privateKey,
    ipnsName: rootIpnsName,
    sequenceNumber: folder.sequenceNumber,
    ctx,
  });

  // 8. Zero sensitive key material
  rootIpnsKeypair.privateKey.fill(0);
  clearBytes(userPrivateKey);

  console.log(
    JSON.stringify({
      folderName: args.folderName,
      oldName: args.folderName,
      newName: args.newName,
      folderSequenceNumber: newSequenceNumber.toString(),
    })
  );
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});
