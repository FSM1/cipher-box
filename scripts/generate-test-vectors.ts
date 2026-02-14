/**
 * CipherBox Test Vector Generator
 *
 * Generates test vectors for the VAULT_EXPORT_FORMAT.md documentation.
 * Uses @cipherbox/crypto (the same library CipherBox uses in production)
 * to ensure vectors are accurate.
 *
 * Run: npx tsx scripts/generate-test-vectors.ts
 */

import * as secp256k1 from '@noble/secp256k1';
import {
  wrapKey,
  unwrapKey,
  encryptFolderMetadata,
  decryptFolderMetadata,
  generateIv,
  hexToBytes,
  bytesToHex,
  type FolderMetadata,
} from '../packages/crypto/dist/index.mjs';

// ---------------------------------------------------------------------------
// Deterministic test data (fixed for reproducibility in documentation)
// ---------------------------------------------------------------------------

// Test private key (32 bytes) - DO NOT use in production
const TEST_PRIVATE_KEY_HEX = '4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d';

// Test folder key (32 bytes) - simulates a root folder AES-256 key
const TEST_FOLDER_KEY_HEX = 'aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd';

// Test IPNS private key (64 bytes) - simulates Ed25519 libp2p format (seed || pubkey)
const TEST_IPNS_KEY_HEX =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' +
  'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';

async function main(): Promise<void> {
  const privateKey = hexToBytes(TEST_PRIVATE_KEY_HEX);
  const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed, 65 bytes
  const folderKey = hexToBytes(TEST_FOLDER_KEY_HEX);
  const ipnsKey = hexToBytes(TEST_IPNS_KEY_HEX);

  console.log('='.repeat(72));
  console.log('CipherBox Test Vector Generator');
  console.log('='.repeat(72));
  console.log();

  // =========================================================================
  // 1. ECIES Test Vector - Root Folder Key
  // =========================================================================
  console.log('--- ECIES Test Vector: Root Folder Key (32 bytes) ---');
  console.log();
  console.log(`Private Key (hex, 32 bytes):`);
  console.log(`  ${TEST_PRIVATE_KEY_HEX}`);
  console.log();
  console.log(`Public Key (uncompressed, hex, 65 bytes):`);
  console.log(`  ${bytesToHex(publicKey)}`);
  console.log();
  console.log(`Plaintext (hex, 32 bytes):`);
  console.log(`  ${TEST_FOLDER_KEY_HEX}`);
  console.log();

  const encryptedFolderKey = await wrapKey(folderKey, publicKey);
  console.log(
    `Encrypted (hex, ${encryptedFolderKey.length} bytes = ${bytesToHex(encryptedFolderKey).length} hex chars):`
  );
  console.log(`  ${bytesToHex(encryptedFolderKey)}`);
  console.log();

  // Round-trip verification
  const decryptedFolderKey = await unwrapKey(encryptedFolderKey, privateKey);
  const folderKeyMatch = bytesToHex(decryptedFolderKey) === TEST_FOLDER_KEY_HEX;
  console.log(`Round-trip verification: ${folderKeyMatch ? 'PASS' : 'FAIL'}`);
  if (!folderKeyMatch) {
    console.error('  Expected:', TEST_FOLDER_KEY_HEX);
    console.error('  Got:     ', bytesToHex(decryptedFolderKey));
    process.exit(1);
  }
  console.log();

  // =========================================================================
  // 2. ECIES Test Vector - IPNS Private Key
  // =========================================================================
  console.log('--- ECIES Test Vector: IPNS Private Key (64 bytes) ---');
  console.log();
  console.log(`Plaintext (hex, 64 bytes):`);
  console.log(`  ${TEST_IPNS_KEY_HEX}`);
  console.log();

  const encryptedIpnsKey = await wrapKey(ipnsKey, publicKey);
  console.log(
    `Encrypted (hex, ${encryptedIpnsKey.length} bytes = ${bytesToHex(encryptedIpnsKey).length} hex chars):`
  );
  console.log(`  ${bytesToHex(encryptedIpnsKey)}`);
  console.log();

  // Round-trip verification
  const decryptedIpnsKey = await unwrapKey(encryptedIpnsKey, privateKey);
  const ipnsKeyMatch = bytesToHex(decryptedIpnsKey) === TEST_IPNS_KEY_HEX;
  console.log(`Round-trip verification: ${ipnsKeyMatch ? 'PASS' : 'FAIL'}`);
  if (!ipnsKeyMatch) {
    console.error('  Expected:', TEST_IPNS_KEY_HEX);
    console.error('  Got:     ', bytesToHex(decryptedIpnsKey));
    process.exit(1);
  }
  console.log();

  // =========================================================================
  // 3. AES-256-GCM Folder Metadata Test Vector
  // =========================================================================
  console.log('--- AES-256-GCM Folder Metadata Test Vector ---');
  console.log();

  // Create sample metadata matching the FolderMetadata type
  const sampleFileKeyEncrypted = bytesToHex(
    await wrapKey(
      hexToBytes('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'),
      publicKey
    )
  );
  const sampleFileIv = bytesToHex(generateIv());

  const sampleMetadata: FolderMetadata = {
    version: 'v1',
    children: [
      {
        type: 'file',
        id: 'test-file-001',
        name: 'hello.txt',
        cid: 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
        fileKeyEncrypted: sampleFileKeyEncrypted,
        fileIv: sampleFileIv,
        encryptionMode: 'GCM' as const,
        size: 13,
        createdAt: 1705268100000,
        modifiedAt: 1705268100000,
      },
    ],
  };

  const plaintextJson = JSON.stringify(sampleMetadata);
  console.log(`Folder Key (hex, 32 bytes):`);
  console.log(`  ${TEST_FOLDER_KEY_HEX}`);
  console.log();
  console.log(`Plaintext JSON:`);
  console.log(`  ${plaintextJson}`);
  console.log();

  const encryptedMetadata = await encryptFolderMetadata(sampleMetadata, folderKey);
  console.log(`Encrypted output:`);
  console.log(`  iv (hex, 12 bytes): ${encryptedMetadata.iv}`);
  console.log(`  data (base64): ${encryptedMetadata.data}`);
  console.log();

  // Round-trip verification
  const decryptedMetadata = await decryptFolderMetadata(encryptedMetadata, folderKey);
  const metadataMatch =
    decryptedMetadata.version === 'v1' &&
    decryptedMetadata.children.length === 1 &&
    decryptedMetadata.children[0].name === 'hello.txt';
  console.log(`Round-trip verification: ${metadataMatch ? 'PASS' : 'FAIL'}`);
  if (!metadataMatch) {
    console.error('  Decrypted metadata does not match original');
    process.exit(1);
  }
  console.log();

  // =========================================================================
  // 4. Sample Export JSON
  // =========================================================================
  console.log('--- Sample Export JSON ---');
  console.log();

  const sampleExport = {
    format: 'cipherbox-vault-export',
    version: '1.0',
    exportedAt: '2026-02-11T00:00:00.000Z',
    rootIpnsName: 'k51qzi5uqu5dg05y48rp46k4yq2tse4ufqfhn6w4i6js3t456ss9dkk',
    encryptedRootFolderKey: bytesToHex(encryptedFolderKey),
    encryptedRootIpnsPrivateKey: bytesToHex(encryptedIpnsKey),
    derivationInfo: {
      method: 'web3auth',
      derivationVersion: null,
    },
  };

  console.log(JSON.stringify(sampleExport, null, 2));
  console.log();

  // =========================================================================
  // Summary
  // =========================================================================
  console.log('='.repeat(72));
  console.log('All test vectors generated and verified successfully.');
  console.log();
  console.log('ECIES ciphertext sizes:');
  console.log(
    `  Folder key (32-byte plaintext): ${encryptedFolderKey.length} bytes = ${bytesToHex(encryptedFolderKey).length} hex chars`
  );
  console.log(
    `  IPNS key (64-byte plaintext):   ${encryptedIpnsKey.length} bytes = ${bytesToHex(encryptedIpnsKey).length} hex chars`
  );
  console.log();
  console.log('Expected sizes per spec:');
  console.log('  Folder key: 129 bytes = 258 hex chars (97 header + 32 plaintext)');
  console.log('  IPNS key:   161 bytes = 322 hex chars (97 header + 64 plaintext)');
  console.log('='.repeat(72));
}

main().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
