/**
 * Generate cross-language test vectors for Rust crypto module verification.
 *
 * Uses @cipherbox/crypto TypeScript module to produce deterministic test vectors
 * that the Rust tests will verify against.
 *
 * Usage: node generate-test-vectors.mjs
 * Requires: pnpm build in packages/crypto first
 */

import {
  encryptAesGcm,
  decryptAesGcm,
  sealAesGcm,
  unsealAesGcm,
  wrapKey,
  unwrapKey,
  signEd25519,
  verifyEd25519,
  createIpnsRecord,
  marshalIpnsRecord,
  deriveIpnsName,
  hexToBytes,
  bytesToHex,
} from '../../../packages/crypto/dist/index.mjs';

import { getPublicKey } from '../../../packages/crypto/node_modules/@noble/secp256k1/index.js';
import * as ed from '../../../packages/crypto/node_modules/@noble/ed25519/index.js';

function toHex(bytes) {
  return bytesToHex(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
}

async function main() {
  console.log('=== CipherBox Cross-Language Test Vectors ===\n');

  // ---- Fixed keys for deterministic tests ----

  // AES key (32 bytes)
  const aesKey = hexToBytes('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
  // AES IV (12 bytes)
  const aesIv = hexToBytes('aabbccddeeff00112233aabb');
  // Plaintext
  const plaintext = new TextEncoder().encode('Hello, CipherBox!');

  // 1. AES-256-GCM with fixed key and IV
  console.log('--- AES-256-GCM Test Vector ---');
  const ciphertext = await encryptAesGcm(plaintext, aesKey, aesIv);
  console.log(`AES_KEY: "${toHex(aesKey)}"`);
  console.log(`AES_IV: "${toHex(aesIv)}"`);
  console.log(`PLAINTEXT: "Hello, CipherBox!"`);
  console.log(`PLAINTEXT_HEX: "${toHex(plaintext)}"`);
  console.log(`CIPHERTEXT_WITH_TAG: "${toHex(ciphertext)}"`);
  console.log(`CIPHERTEXT_LEN: ${ciphertext.length}`);
  console.log();

  // Verify round-trip
  const decrypted = await decryptAesGcm(ciphertext, aesKey, aesIv);
  console.log(`DECRYPTED: "${new TextDecoder().decode(decrypted)}"`);
  console.log();

  // 2. AES seal (uses random IV, so we produce a sealed blob and verify the format)
  console.log('--- AES Seal Format Test Vector ---');
  const sealed = await sealAesGcm(plaintext, aesKey);
  console.log(`SEALED_HEX: "${toHex(sealed)}"`);
  console.log(`SEALED_LEN: ${sealed.length}`);
  // Extract IV from sealed to verify unsealing works
  const sealedIv = sealed.slice(0, 12);
  console.log(`SEALED_IV: "${toHex(sealedIv)}"`);
  const unsealed = await unsealAesGcm(sealed, aesKey);
  console.log(`UNSEALED: "${new TextDecoder().decode(unsealed)}"`);
  console.log();

  // 3. Ed25519 with fixed private key
  console.log('--- Ed25519 Test Vector ---');
  const ed25519PrivateKey = hexToBytes(
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
  );
  const ed25519PublicKey = ed.getPublicKey(ed25519PrivateKey);
  console.log(`ED25519_PRIVATE_KEY: "${toHex(ed25519PrivateKey)}"`);
  console.log(`ED25519_PUBLIC_KEY: "${toHex(ed25519PublicKey)}"`);

  const message = new TextEncoder().encode('Hello, CipherBox!');
  const signature = await signEd25519(message, ed25519PrivateKey);
  console.log(`ED25519_MESSAGE: "Hello, CipherBox!"`);
  console.log(`ED25519_SIGNATURE: "${toHex(signature)}"`);
  console.log(`ED25519_SIGNATURE_LEN: ${signature.length}`);

  const valid = await verifyEd25519(signature, message, ed25519PublicKey);
  console.log(`ED25519_VERIFY: ${valid}`);
  console.log();

  // 4. ECIES with fixed secp256k1 keypair
  console.log('--- ECIES Test Vector ---');
  const eciesPrivateKey = hexToBytes(
    'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721'
  );
  const eciesPublicKey = getPublicKey(eciesPrivateKey, false); // uncompressed
  console.log(`ECIES_PRIVATE_KEY: "${toHex(eciesPrivateKey)}"`);
  console.log(`ECIES_PUBLIC_KEY: "${toHex(eciesPublicKey)}"`);

  // ECIES is non-deterministic (ephemeral key), so we wrap and provide the wrapped bytes
  // for Rust to unwrap. We also test Rust -> TS direction via round-trip test.
  const eciesPlaintext = hexToBytes(
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
  );
  const wrapped = await wrapKey(eciesPlaintext, eciesPublicKey);
  console.log(`ECIES_PLAINTEXT: "${toHex(eciesPlaintext)}"`);
  console.log(`ECIES_WRAPPED: "${toHex(wrapped)}"`);
  console.log(`ECIES_WRAPPED_LEN: ${wrapped.length}`);

  // Verify unwrap
  const unwrapped = await unwrapKey(wrapped, eciesPrivateKey);
  console.log(`ECIES_UNWRAPPED: "${toHex(unwrapped)}"`);
  console.log(`ECIES_ROUNDTRIP: ${toHex(unwrapped) === toHex(eciesPlaintext)}`);
  console.log();

  // 5. IPNS Record with fixed Ed25519 keypair and fixed timestamp
  console.log('--- IPNS Record Test Vector ---');
  const ipnsPrivateKey = hexToBytes(
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
  );
  const ipnsPublicKey = ed.getPublicKey(ipnsPrivateKey);
  const ipnsValue = '/ipfs/bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4';
  const ipnsSequence = 42n;
  const ipnsLifetimeMs = 86400000; // 24h

  console.log(`IPNS_PRIVATE_KEY: "${toHex(ipnsPrivateKey)}"`);
  console.log(`IPNS_PUBLIC_KEY: "${toHex(ipnsPublicKey)}"`);
  console.log(`IPNS_VALUE: "${ipnsValue}"`);
  console.log(`IPNS_SEQUENCE: ${ipnsSequence}`);
  console.log(`IPNS_LIFETIME_MS: ${ipnsLifetimeMs}`);

  const ipnsRecord = await createIpnsRecord(
    ipnsPrivateKey,
    ipnsValue,
    ipnsSequence,
    ipnsLifetimeMs
  );
  console.log(`IPNS_VALIDITY: "${ipnsRecord.validity}"`);
  console.log(`IPNS_SIGNATURE_V2: "${toHex(ipnsRecord.signatureV2)}"`);
  console.log(`IPNS_SIGNATURE_V2_LEN: ${ipnsRecord.signatureV2.length}`);
  console.log(`IPNS_DATA_CBOR: "${toHex(ipnsRecord.data)}"`);
  console.log(`IPNS_DATA_CBOR_LEN: ${ipnsRecord.data.length}`);

  if (ipnsRecord.signatureV1) {
    console.log(`IPNS_SIGNATURE_V1: "${toHex(ipnsRecord.signatureV1)}"`);
    console.log(`IPNS_SIGNATURE_V1_LEN: ${ipnsRecord.signatureV1.length}`);
  }

  const marshaled = marshalIpnsRecord(ipnsRecord);
  console.log(`IPNS_MARSHALED: "${toHex(marshaled)}"`);
  console.log(`IPNS_MARSHALED_LEN: ${marshaled.length}`);
  console.log();

  // 6. IPNS Name Derivation
  console.log('--- IPNS Name Derivation Test Vector ---');
  const ipnsName = await deriveIpnsName(ipnsPublicKey);
  console.log(`IPNS_NAME: "${ipnsName}"`);
  console.log(`IPNS_NAME_PUBLIC_KEY: "${toHex(ipnsPublicKey)}"`);
  console.log();

  console.log('=== Test Vector Generation Complete ===');
}

main().catch(console.error);
