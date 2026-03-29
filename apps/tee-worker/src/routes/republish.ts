/**
 * Republish Route
 *
 * POST /republish - Batch IPNS record signing endpoint.
 *
 * Receives encrypted IPNS private keys, decrypts with epoch-derived keys,
 * signs IPNS records, and returns signed records. Each entry is processed
 * independently -- one failure does not block others.
 *
 * SECURITY:
 * - IPNS private keys are zeroed immediately after signing
 * - No key material appears in logs or error messages
 * - Per-entry error handling with safe error messages
 */

import { Router, type Request, type Response } from 'express';
import { decryptWithFallback, reEncryptForEpoch } from '../services/key-manager.js';
import { signIpnsRecord } from '../services/ipns-signer.js';

const router = Router();

/** Shape of each entry in the republish request */
interface RepublishEntry {
  encryptedIpnsKey: string; // base64-encoded ECIES ciphertext
  keyEpoch: number;
  ipnsName: string;
  latestCid: string;
  sequenceNumber: string; // bigint as string
  currentEpoch: number;
  previousEpoch: number | null;
}

/** Shape of each result in the republish response */
interface RepublishResult {
  ipnsName: string;
  success: boolean;
  signedRecord?: string; // base64-encoded marshaled IPNS record
  newSequenceNumber?: string;
  upgradedEncryptedKey?: string; // base64, present if re-encrypted for current epoch
  upgradedKeyEpoch?: number;
  error?: string;
}

router.post('/republish', async (req: Request, res: Response) => {
  const { entries } = req.body as { entries: RepublishEntry[] };

  if (!entries || !Array.isArray(entries)) {
    res.status(400).json({ error: 'Missing or invalid entries array' });
    return;
  }

  const results: RepublishResult[] = [];
  let successes = 0;
  let failures = 0;

  for (const entry of entries) {
    let ipnsPrivateKey: Uint8Array | null = null;

    try {
      // 1. Decode encrypted IPNS key from base64
      const encryptedIpnsKey = new Uint8Array(Buffer.from(entry.encryptedIpnsKey, 'base64'));

      // 2. Decrypt with epoch fallback
      const { ipnsPrivateKey: decryptedKey, usedEpoch } = await decryptWithFallback(
        encryptedIpnsKey,
        entry.currentEpoch,
        entry.previousEpoch
      );
      ipnsPrivateKey = decryptedKey;

      // 3. Sign IPNS record with incremented sequence number
      const newSequenceNumber = BigInt(entry.sequenceNumber) + 1n;
      const signedRecord = await signIpnsRecord(ipnsPrivateKey, entry.latestCid, newSequenceNumber);

      // 4. Check if re-encryption needed (used previous epoch, not current)
      let upgradedEncryptedKey: string | undefined;
      let upgradedKeyEpoch: number | undefined;

      if (usedEpoch !== entry.currentEpoch) {
        const reEncrypted = await reEncryptForEpoch(ipnsPrivateKey, entry.currentEpoch);
        upgradedEncryptedKey = Buffer.from(reEncrypted).toString('base64');
        upgradedKeyEpoch = entry.currentEpoch;
      }

      // 5. IMMEDIATELY zero the IPNS private key
      ipnsPrivateKey.fill(0);
      ipnsPrivateKey = null;

      // 6. Build success result
      const result: RepublishResult = {
        ipnsName: entry.ipnsName,
        success: true,
        signedRecord: Buffer.from(signedRecord).toString('base64'),
        newSequenceNumber: newSequenceNumber.toString(),
      };

      if (upgradedEncryptedKey) {
        result.upgradedEncryptedKey = upgradedEncryptedKey;
        result.upgradedKeyEpoch = upgradedKeyEpoch;
      }

      results.push(result);
      successes++;
    } catch (error) {
      // Ensure key is zeroed even on error
      if (ipnsPrivateKey) {
        ipnsPrivateKey.fill(0);
        ipnsPrivateKey = null;
      }

      // Never include key material in error messages
      results.push({
        ipnsName: entry.ipnsName,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      failures++;
    }
  }

  // Log processing summary (NEVER log key material)
  console.log(
    `Republish batch: ${entries.length} entries, ${successes} successes, ${failures} failures`
  );

  res.json({ results });
});

export default router;
