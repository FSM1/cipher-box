/**
 * Generates a complete demo vault with real AES-256-GCM encryption.
 * ECIES-wrapped keys use pre-computed realistic hex values since
 * secp256k1 isn't available in Web Crypto.
 *
 * The vault structure:
 *   VaultKey (secp256k1)
 *     └ Root Folder (IPNS: rootIpnsName)
 *         ├ FolderEntry: "Documents" (IPNS: docsIpnsName)
 *         └ FilePointer: "secret-note.txt" (IPNS: fileIpnsName)
 *
 *   File content: plaintext string encrypted with AES-256-GCM
 */

import {
  hexEncode,
  hexDecode,
  base64Encode,
  aesGcmEncrypt,
  encryptMetadata,
  decryptMetadata,
  computeCid,
} from './demo-crypto';

// ---- Fixed demo keys (deterministic for reproducibility) ----

// secp256k1 VaultKey (demo only - never use real keys on a public page!)
export const VAULT_PRIVATE_KEY = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3';
export const VAULT_PUBLIC_KEY =
  '04' +
  '7d3e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6' +
  'e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9';

// AES-256 keys (32 bytes each)
export const ROOT_FOLDER_KEY = '9f8e7d6c5b4a39281706f5e4d3c2b1a00a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d';
export const DOCS_FOLDER_KEY = '1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809';
export const FILE_KEY = 'deadbeef0123456789abcdef01234567fedcba9876543210abcdef0123456789ab';

// IVs (12 bytes each)
export const ROOT_FOLDER_IV = 'aabbccddeeff001122334455';
export const DOCS_FOLDER_IV = '112233445566778899aabbcc';
export const FILE_META_IV = 'ffeeddccbbaa998877665544';
export const FILE_CONTENT_IV = '0a1b2c3d4e5f6a7b8c9d0e1f';

// IPNS names (realistic k51... format)
export const ROOT_IPNS_NAME = 'k51qzi5uqu5dgrce6o36s5e2vr46huv5645rqfqy2mxqgz43hf7c7vnlkd5e';
export const DOCS_IPNS_NAME = 'k51qzi5uqu5dh6uxedga74ty41q9w3mv8frnkiw6aqp5gny7m9dkj46bze3';
export const FILE_IPNS_NAME = 'k51qzi5uqu5djb7rfno3p8ks5q2d8yc4a91gnvt64z3xh2wj5m7nk82jwe9';

// Pre-computed ECIES-wrapped keys (65-byte ephemeral + 32-byte cipher + 16-byte tag = 113 bytes = 226 hex)
// These are realistic-length hex strings matching the actual ECIES output format
export const ROOT_FOLDER_KEY_ECIES =
  '04e3a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0' +
  'f9e8d7c6b5a493827160f5e4d3c2b1a0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6' +
  'aabbccddeeff00112233445566778899aabbccddeeff0011';

export const DOCS_FOLDER_KEY_ECIES =
  '04f4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5' +
  '1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809' +
  '99887766554433221100ffeeddccbbaa99887766554433';

export const FILE_KEY_ECIES =
  '04a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8' +
  'deadbeef0123456789abcdef01234567fedcba9876543210abcdef0123456789ab' +
  '00112233445566778899aabbccddeeff00112233445566';

// Pre-computed ECIES-wrapped IPNS private keys (65 + 32 + 16 = 113 bytes for 32-byte seed)
export const DOCS_IPNS_KEY_ECIES =
  '04c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2' +
  '7788990011223344556677889900aabbccddeeff00112233445566778899aabbcc' +
  'ffeeddccbbaa99887766554433221100ffeeddccbbaa99';

export const FILE_IPNS_KEY_ECIES =
  '04d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3' +
  'aabb0011223344556677889900aabbccddeeff00112233445566778899aabbcc00' +
  '0123456789abcdef0123456789abcdef0123456789abcd';

// File plaintext
export const FILE_PLAINTEXT =
  'Hello from CipherBox! This message was encrypted client-side ' +
  'using AES-256-GCM before it ever left your device. The server ' +
  'never sees this text, the file name, or any encryption keys.';

// ---- Types ----

export interface DemoVault {
  // Plaintext metadata objects
  rootFolderMeta: object;
  docsFolderMeta: object;
  fileMeta: object;

  // Encrypted metadata blobs (wire format)
  rootFolderEncrypted: { iv: string; data: string };
  docsFolderEncrypted: { iv: string; data: string };
  fileMetaEncrypted: { iv: string; data: string };

  // Encrypted file content
  fileContentEncrypted: string; // base64 of ciphertext+tag

  // Content-addressed identifiers
  rootFolderCid: string;
  docsFolderCid: string;
  fileMetaCid: string;
  fileContentCid: string;
}

// Bob's keys for sharing demo
export const BOB_PRIVATE_KEY = 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4';
export const BOB_PUBLIC_KEY =
  '04' +
  'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3' +
  'f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6';

// fileKey re-wrapped with Bob's public key
export const FILE_KEY_ECIES_BOB =
  '04b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7' +
  'ef01234567890abcdefdcba9876543210fedcba9876543210abcdef0123456789' +
  'aabbccddeeff00112233445566778899aabbccddeeff00';

// ---- Vault generator ----

export async function generateDemoVault(): Promise<DemoVault> {
  const rootFolderKeyBytes = hexDecode(ROOT_FOLDER_KEY);
  const docsFolderKeyBytes = hexDecode(DOCS_FOLDER_KEY);
  const fileKeyBytes = hexDecode(FILE_KEY);

  const now = Date.now();
  const hourAgo = now - 3600000;

  // 1. Build plaintext metadata objects (matching CipherBox schemas exactly)

  const fileMeta = {
    version: 'v1' as const,
    cid: '', // Will be computed after encrypting file content
    fileKeyEncrypted: FILE_KEY_ECIES,
    fileIv: FILE_CONTENT_IV,
    size: FILE_PLAINTEXT.length,
    mimeType: 'text/plain',
    encryptionMode: 'GCM' as const,
    createdAt: hourAgo,
    modifiedAt: hourAgo,
  };

  // Encrypt the actual file content
  const filePlainBytes = new TextEncoder().encode(FILE_PLAINTEXT);
  const fileIvBytes = hexDecode(FILE_CONTENT_IV);
  const { ciphertext: fileCipher, tag: fileTag } = await aesGcmEncrypt(filePlainBytes, fileKeyBytes, fileIvBytes);
  const fileCiphertextWithTag = new Uint8Array(fileCipher.length + fileTag.length);
  fileCiphertextWithTag.set(fileCipher);
  fileCiphertextWithTag.set(fileTag, fileCipher.length);

  const fileContentCid = await computeCid(fileCiphertextWithTag);
  fileMeta.cid = fileContentCid;

  const rootFolderMeta = {
    version: 'v2' as const,
    children: [
      {
        type: 'folder' as const,
        id: '550e8400-e29b-41d4-a716-446655440000',
        name: 'Documents',
        ipnsName: DOCS_IPNS_NAME,
        ipnsPrivateKeyEncrypted: DOCS_IPNS_KEY_ECIES,
        folderKeyEncrypted: DOCS_FOLDER_KEY_ECIES,
        createdAt: hourAgo,
        modifiedAt: now,
      },
      {
        type: 'file' as const,
        id: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
        name: 'secret-note.txt',
        fileMetaIpnsName: FILE_IPNS_NAME,
        ipnsPrivateKeyEncrypted: FILE_IPNS_KEY_ECIES,
        createdAt: hourAgo,
        modifiedAt: hourAgo,
      },
    ],
  };

  const docsFolderMeta = {
    version: 'v2' as const,
    children: [],
  };

  // 2. Encrypt metadata blobs

  const rootFolderEncrypted = await encryptMetadata(
    rootFolderMeta,
    rootFolderKeyBytes,
    hexDecode(ROOT_FOLDER_IV)
  );

  const docsFolderEncrypted = await encryptMetadata(
    docsFolderMeta,
    docsFolderKeyBytes,
    hexDecode(DOCS_FOLDER_IV)
  );

  const fileMetaEncrypted = await encryptMetadata(
    fileMeta,
    rootFolderKeyBytes, // File metadata encrypted with parent folder's key
    hexDecode(FILE_META_IV)
  );

  // 3. Compute CIDs from encrypted blobs

  const rootFolderCid = await computeCid(new TextEncoder().encode(JSON.stringify(rootFolderEncrypted)));
  const docsFolderCid = await computeCid(new TextEncoder().encode(JSON.stringify(docsFolderEncrypted)));
  const fileMetaCid = await computeCid(new TextEncoder().encode(JSON.stringify(fileMetaEncrypted)));

  return {
    rootFolderMeta,
    docsFolderMeta,
    fileMeta,
    rootFolderEncrypted,
    docsFolderEncrypted,
    fileMetaEncrypted,
    fileContentEncrypted: base64Encode(fileCiphertextWithTag),
    rootFolderCid,
    docsFolderCid,
    fileMetaCid,
    fileContentCid,
  };
}
