/**
 * REQ-4 / #5 — share itemName ECIES at-rest helpers.
 *
 * Covers the pure helper wired into share.service.ts:
 *  - decryptItemName: ciphertext path (unwrap with vault private key) + legacy
 *    plaintext fallback (no ciphertext present).
 *
 * The lazy plaintext-backfill decision predicate (shouldBackfill) was removed
 * (GAP-6, 68.1-24) — the item_name column was dropped in the Phase 66 schema
 * cutover, making it permanently-unreachable dead code.
 *
 * Security: fixtures use the real wrapKey/unwrapKey ECIES primitive with a
 * generated keypair. Never log itemName/itemNameEncrypted.
 */
import { describe, it, expect } from 'vitest';
import * as secp256k1 from '@noble/secp256k1';
import { wrapKey, bytesToHex } from '@cipherbox/crypto';
import { decryptItemName } from '../share.service';

function generateTestKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  // @noble/secp256k1 v3: randomSecretKey() (v1 randomPrivateKey() was renamed)
  const privateKey = secp256k1.utils.randomSecretKey();
  const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed
  return { publicKey, privateKey };
}

async function wrapName(name: string, publicKey: Uint8Array): Promise<string> {
  return bytesToHex(await wrapKey(new TextEncoder().encode(name), publicKey));
}

describe('decryptItemName', () => {
  it('unwraps itemNameEncrypted to the UTF-8 display name with the vault private key', async () => {
    const recipient = generateTestKeypair();
    const name = 'Secret Tax Docs';
    const itemNameEncrypted = await wrapName(name, recipient.publicKey);

    const result = await decryptItemName({ itemName: '', itemNameEncrypted }, recipient.privateKey);

    expect(result).toBe(name);
  });

  it('round-trips a multibyte UTF-8 name', async () => {
    const recipient = generateTestKeypair();
    const name = 'Réсumé 機密 📄';
    const itemNameEncrypted = await wrapName(name, recipient.publicKey);

    const result = await decryptItemName({ itemName: '', itemNameEncrypted }, recipient.privateKey);

    expect(result).toBe(name);
  });

  it('falls back to legacy plaintext itemName when no ciphertext is present', async () => {
    const recipient = generateTestKeypair();

    const result = await decryptItemName(
      { itemName: 'legacy-plaintext.txt', itemNameEncrypted: null },
      recipient.privateKey
    );

    expect(result).toBe('legacy-plaintext.txt');
  });

  it('falls back to plaintext when ciphertext is an empty string', async () => {
    const recipient = generateTestKeypair();

    const result = await decryptItemName(
      { itemName: 'legacy.txt', itemNameEncrypted: '' },
      recipient.privateKey
    );

    expect(result).toBe('legacy.txt');
  });
});
