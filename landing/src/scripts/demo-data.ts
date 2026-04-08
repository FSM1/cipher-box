/**
 * Pre-computed demo vault data. All values are static — no Web Crypto needed.
 * The hex strings match realistic CipherBox output formats and lengths.
 */

// ---- Demo VaultKey (secp256k1) ----

export const VAULT_PRIVATE_KEY = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3';
export const VAULT_PUBLIC_KEY =
  '04' +
  '7d3e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6' +
  'e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9';

// ---- AES-256 keys ----

export const ROOT_FOLDER_KEY = '9f8e7d6c5b4a39281706f5e4d3c2b1a00a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d';
export const DOCS_FOLDER_KEY = '1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809';
export const FILE_KEY = 'deadbeef0123456789abcdef01234567fedcba9876543210abcdef0123456789ab';

// ---- IPNS names ----

export const ROOT_IPNS = 'k51qzi5uqu5dgrce6o36s5e2vr46huv5645rqfqy2mxqgz43hf7c7vnlkd5e';
export const DOCS_IPNS = 'k51qzi5uqu5dh6uxedga74ty41q9w3mv8frnkiw6aqp5gny7m9dkj46bze3';
export const FILE_IPNS = 'k51qzi5uqu5djb7rfno3p8ks5q2d8yc4a91gnvt64z3xh2wj5m7nk82jwe9';

// ---- IPFS CIDs ----

export const ROOT_FOLDER_CID = 'bafybeigrf2dwtpjkiovnigysyto3d4e2cxwz7sxi3qym34tvnvwaksgm4u';
export const DOCS_FOLDER_CID = 'bafybeihq4lpnv6fsc2zv7m3n5x8kd2jt3q9ypfhwk7vxnblzse6ym3gui';
export const FILE_META_CID = 'bafybeiclmn7k4rx5jxp3xzfg8qw2hdy6t9ve7kj4n3m8zl2xsa5uodrq4';
export const FILE_CONTENT_CID = 'bafybeif4ogy7xtnreqae2bkzlk7yxmo5jchbvcn3d6rph3kds4xr2wmfea';

// ---- Pre-computed ECIES-wrapped keys (realistic lengths) ----

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

export const DOCS_IPNS_KEY_ECIES =
  '04c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2' +
  '7788990011223344556677889900aabbccddeeff00112233445566778899aabbcc' +
  'ffeeddccbbaa99887766554433221100ffeeddccbbaa99';

export const FILE_IPNS_KEY_ECIES =
  '04d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3' +
  'aabb0011223344556677889900aabbccddeeff00112233445566778899aabbcc00' +
  '0123456789abcdef0123456789abcdef0123456789abcd';

// ---- File content ----

export const FILE_PLAINTEXT =
  'Hello from CipherBox! This message was encrypted client-side ' +
  'using AES-256-GCM before it ever left your device. The server ' +
  'never sees this text, the file name, or any encryption keys.';

// ---- Pre-computed encrypted blobs (AES-256-GCM output as base64) ----

// Encrypted root folder metadata
export const ROOT_FOLDER_ENCRYPTED = {
  iv: 'aabbccddeeff001122334455',
  data: 'S2w4ajVSKzJWcXhYWXpCOWtNNG5QMnBRclN0K1VuVndYeVowYUIxY0QyZUYzZ0g0aUo1a0w2bU43b084cFA5cVI9PQ==',
};

// Encrypted docs folder metadata
export const DOCS_FOLDER_ENCRYPTED = {
  iv: '112233445566778899aabbcc',
  data: 'YjN4cDdrMmZqOHF3NXY2dTl5OHI3dDZzNWU0ZDNjMmIxYTA=',
};

// Encrypted file metadata
export const FILE_META_ENCRYPTED = {
  iv: 'ffeeddccbbaa998877665544',
  data: 'Vk9NR2NtVndaM1JoZEdseGEzTnlkSFEzTmpVME16SXhNREU1T0RjMk5UUXpNakV3TVRrd01EZzNOalUwTXpJeE1ERTVPRGMyTlRRek1qRXdNVGs0TURjMk5UUXo=',
};

// Encrypted file content
export const FILE_CONTENT_ENCRYPTED =
  'cjdXNGIzYzJkMWUwZjlhOGI3YzZkNWU0ZjNhMmIxYzBkOWU4ZjdhNmI1YzRkM2UyZjFhMGI5YzhlN2Y2YTViNGMzZDJlMWYwYTliOGM3ZDZlNWY0YTNiMmMxZDBl';

// ---- Plaintext metadata objects (what you see after decryption) ----

export const ROOT_FOLDER_META = {
  version: 'v2',
  children: [
    {
      type: 'folder',
      id: '550e8400-e29b-41d4-a716-446655440000',
      name: 'Documents',
      ipnsName: DOCS_IPNS,
      ipnsPrivateKeyEncrypted: DOCS_IPNS_KEY_ECIES,
      folderKeyEncrypted: DOCS_FOLDER_KEY_ECIES,
      createdAt: 1712534400000,
      modifiedAt: 1712538000000,
    },
    {
      type: 'file',
      id: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
      name: 'secret-note.txt',
      fileMetaIpnsName: FILE_IPNS,
      ipnsPrivateKeyEncrypted: FILE_IPNS_KEY_ECIES,
      createdAt: 1712534400000,
      modifiedAt: 1712534400000,
    },
  ],
};

export const DOCS_FOLDER_META = {
  version: 'v2',
  children: [],
};

export const FILE_META = {
  version: 'v1',
  cid: FILE_CONTENT_CID,
  fileKeyEncrypted: FILE_KEY_ECIES,
  fileIv: '0a1b2c3d4e5f6a7b8c9d0e1f',
  size: FILE_PLAINTEXT.length,
  mimeType: 'text/plain',
  encryptionMode: 'GCM',
  createdAt: 1712534400000,
  modifiedAt: 1712534400000,
};

// ---- Bob's keys for sharing demo ----

export const BOB_PRIVATE_KEY = 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4';
export const BOB_PUBLIC_KEY =
  '04' +
  'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3' +
  'f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6';

export const FILE_KEY_ECIES_BOB =
  '04b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7' +
  'ef01234567890abcdefdcba9876543210fedcba9876543210abcdef0123456789' +
  'aabbccddeeff00112233445566778899aabbccddeeff00';

// ---- Utility ----

export function truncHex(hex: string, show = 8): string {
  if (hex.length <= show * 2 + 3) return hex;
  return hex.slice(0, show) + '...' + hex.slice(-show);
}
