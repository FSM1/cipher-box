/**
 * edit-filepointer.mjs -- Edit a file's content via the SDK.
 *
 * Authenticates via test-login, finds the target file in the vault,
 * encrypts new content, uploads to IPFS, updates the file's IPNS
 * metadata record, and republishes folder metadata with an updated
 * modified_at timestamp so other clients (e.g. FUSE mount) detect
 * the change.
 *
 * Usage:
 *   TEST_SECRET=<secret> node edit-filepointer.mjs \
 *     --api-url http://localhost:3000 \
 *     --email dev-key@cipherbox.local \
 *     --file-name hello.txt \
 *     --new-content "Updated content from SDK"
 */

import { createAxiosInstance } from '../../api-client/dist/index.mjs';
import {
  loadVaultKeyBlob,
  loadFolderMetadata,
  resolveFileMetadata,
  updateFileMetadata,
  updateFolderMetadataAndPublish,
} from '../dist/index.mjs';
import {
  encryptAesGcm,
  generateFileKey,
  generateIv,
  wrapKey,
  unwrapKey,
  bytesToHex,
  hexToBytes,
  deriveVaultIpnsKeypair,
  clearBytes,
} from '../../crypto/dist/index.mjs';
import { addToIpfs } from '../dist/index.mjs';

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
  const fileName = values.get('file-name');
  const newContent = values.get('new-content');

  if (!apiUrl || !email || !fileName || !secret || newContent === undefined) {
    throw new Error(
      'Usage: edit-filepointer.mjs --api-url <url> --email <email> --file-name <name> --new-content <text> (requires TEST_SECRET env var)'
    );
  }

  return { apiUrl, secret, email, fileName, newContent };
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
  const userPublicKey = Uint8Array.from(Buffer.from(auth.publicKeyHex, 'hex'));

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

  // 4. Find the target file's FilePointer
  const filePointer = folder.metadata.children.find(
    (child) => child.type === 'file' && child.name === args.fileName
  );
  if (!filePointer) {
    throw new Error(`FilePointer not found for ${args.fileName}`);
  }
  if (!filePointer.fileMetaIpnsName) {
    throw new Error(`FilePointer for ${args.fileName} is missing fileMetaIpnsName`);
  }

  // 5. Resolve current file metadata
  const { metadata: currentMetadata } = await resolveFileMetadata(
    filePointer.fileMetaIpnsName,
    vaultKeyBlob.rootFolderKey,
    ctx
  );

  // 6. Decrypt the file IPNS private key from FilePointer
  if (!filePointer.ipnsPrivateKeyEncrypted) {
    throw new Error('FilePointer missing ipnsPrivateKeyEncrypted (legacy files not supported)');
  }
  const fileIpnsPrivateKey = await unwrapKey(
    hexToBytes(filePointer.ipnsPrivateKeyEncrypted),
    userPrivateKey
  );

  // 7. Encrypt new content
  const plaintext = new TextEncoder().encode(args.newContent);
  const fileKey = generateFileKey();
  const iv = generateIv();
  let newCid;
  let wrappedKeyHex;
  let ivHex;

  try {
    const ciphertext = await encryptAesGcm(plaintext, fileKey, iv);
    const wrappedKey = await wrapKey(fileKey, userPublicKey);
    wrappedKeyHex = bytesToHex(wrappedKey);
    ivHex = bytesToHex(iv);

    // 8. Upload encrypted content to IPFS
    const uploadResult = await addToIpfs(ctx, ciphertext);
    newCid = uploadResult.cid;
  } finally {
    clearBytes(fileKey);
  }

  // 9. Update file metadata — publishes the file IPNS record internally with CAS.
  // Contract change (#488): updateFileMetadata now publishes the record itself and
  // returns { ipnsName, metadataCid, newSequenceNumber, prunedCids } — there is no
  // separate replaceFileInFolder step anymore (it would re-publish with undefined
  // fields and be rejected by the API DTO). Mirrors apps/web useFileOperations.ts.
  try {
    await updateFileMetadata({
      fileIpnsPrivateKey,
      fileMetaIpnsName: filePointer.fileMetaIpnsName,
      folderKey: vaultKeyBlob.rootFolderKey,
      currentMetadata,
      updates: {
        cid: newCid,
        fileKeyEncrypted: wrappedKeyHex,
        fileIv: ivHex,
        size: plaintext.length,
        encryptionMode: 'GCM',
      },
      createVersion: true,
      ctx,
    });
  } finally {
    fileIpnsPrivateKey.fill(0);
  }

  // 10. Republish folder metadata with updated modified_at so other clients
  // (e.g. FUSE mount) detect the change via the FilePointer timestamp.
  const updatedChildren = folder.metadata.children.map((child) => {
    if (child.type === 'file' && child.id === filePointer.id) {
      return { ...child, modifiedAt: Date.now() };
    }
    return child;
  });

  // Derive root folder IPNS keypair for republishing
  const rootIpnsKeypair = await deriveVaultIpnsKeypair(userPrivateKey);

  const { newSequenceNumber } = await updateFolderMetadataAndPublish({
    children: updatedChildren,
    // Pre-mutation snapshot is the three-way merge base (folder.metadata.children
    // is the original set; updatedChildren is the post-mutation set).
    baseChildren: folder.metadata.children,
    folderKey: vaultKeyBlob.rootFolderKey,
    ipnsPrivateKey: rootIpnsKeypair.privateKey,
    ipnsName: rootIpnsName,
    sequenceNumber: folder.sequenceNumber,
    ctx,
  });

  // Zero sensitive key material
  rootIpnsKeypair.privateKey.fill(0);

  console.log(
    JSON.stringify({
      fileName: args.fileName,
      oldCid: currentMetadata.cid,
      newCid,
      newContentLength: plaintext.length,
      folderSequenceNumber: newSequenceNumber.toString(),
      fileMetaIpnsName: filePointer.fileMetaIpnsName,
    })
  );
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});
