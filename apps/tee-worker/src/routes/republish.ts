/**
 * Republish Route
 *
 * POST /republish - Verify-in-enclave IPNS lease-renewer (TEE-01 / TEE-02 / TEE-06).
 *
 * Contract (D-01): the relay sends the marshaled existing signedRecord and the encrypted
 * IPNS private key. The TEE:
 *   1. Parses the signedRecord bytes.
 *   2. Verifies the Ed25519 signature against publicKeyFromIpnsName(ipnsName) — BEFORE decryption.
 *   3. Decrypts the key via the internal-epoch fallback (D-03 / 67-02).
 *   4. Asserts the name↔key binding: deriveEd25519PublicKey(decryptedKey) must equal
 *      publicKeyFromIpnsName(ipnsName). NEVER uses parsed.pubKey (undefined for Ed25519
 *      identity records — RESEARCH Pitfall 1).
 *   5. Re-signs the SAME value (CID) + SAME sequence with only a later EOL via renewIpnsRecord.
 *      newSequenceNumber == parsedSequence — no increment (TEE-02 / §7.3 test 12).
 *   6. Optionally re-encrypts the key for the current internal epoch (D-03).
 *   7. Zeros the decrypted key on EVERY path (success, binding-fail, re-enroll, error).
 *
 * REMOVED from request body: latestCid, sequenceNumber, currentEpoch, previousEpoch.
 * The relay MUST NOT send those fields; the TEE MUST NOT read them.
 *
 * Each entry is processed independently — one failure does not block others.
 *
 * SECURITY:
 * - IPNS private keys are zeroed immediately after their last use (T-67-06-I)
 * - No key material appears in logs or error messages
 * - Signature verification precedes decryption (T-67-06-T)
 * - Binding check uses name-derived key, never parsed.pubKey (T-67-06-T2)
 * - Epoch upgrade uses TEE-internal clock, never relay scalars (T-67-06-E)
 */

import { Router, type Request, type Response } from 'express';
import {
  parseIpnsRecord,
  verifyIpnsRecordSignature,
  publicKeyFromIpnsName,
  deriveEd25519PublicKey,
} from '@cipherbox/crypto';
import {
  decryptWithFallback,
  reEncryptForEpoch,
  ReEnrollRequiredError,
} from '../services/key-manager.js';
import { renewIpnsRecord } from '../services/ipns-signer.js';
import { getInternalCurrentEpoch } from '../services/tee-keys.js';
import { republishEntries } from '../middleware/metrics.js';
import { logger } from '../services/logger.js';

const router = Router();

/**
 * Shape of each entry in the republish request (D-01 / D-02 / D-03 contract).
 *
 * Removed from v1: latestCid, sequenceNumber, currentEpoch, previousEpoch.
 * All signing inputs come from the marshaled signedRecord; epoch is self-derived.
 */
interface RepublishEntry {
  encryptedIpnsPrivateKey: string; // base64-encoded ECIES ciphertext of the IPNS Ed25519 private key
  keyEpoch: number; // epoch the key is recorded as encrypted for (from ipns_records.key_epoch)
  ipnsName: string; // IPNS name (CIDv1 base36)
  signedRecord: string; // base64-encoded marshaled existing IPNS record
}

/** Shape of each result in the republish response */
interface RepublishResult {
  ipnsName: string;
  success: boolean;
  signedRecord?: string; // base64-encoded marshaled renewed IPNS record (same CID + seq, later EOL)
  newSequenceNumber?: string; // equals the parsed input sequence (no increment)
  upgradedEncryptedKey?: string; // base64, present if key was re-encrypted for current epoch
  upgradedKeyEpoch?: number;
  requiresReEnroll?: true; // present when ReEnrollRequiredError thrown (T-67-06-I)
  error?: string;
}

router.post('/republish', async (req: Request, res: Response) => {
  const { entries } = req.body as { entries: RepublishEntry[] };

  if (!entries || !Array.isArray(entries)) {
    res.status(400).json({ error: 'Missing or invalid entries array' });
    return;
  }

  const MAX_BATCH_SIZE = 100;
  if (entries.length > MAX_BATCH_SIZE) {
    res
      .status(400)
      .json({ error: `Batch too large: ${entries.length} entries (max ${MAX_BATCH_SIZE})` });
    return;
  }

  const results: RepublishResult[] = [];

  for (const entry of entries) {
    // ── Per-entry defense-in-depth guard (T-76-08) ──────────────────────────
    // A null / non-object entry must never crash the whole batch: skip it with a
    // per-entry failure BEFORE the try, so the catch block below can never
    // dereference a null `entry.ipnsName`. The relay is trusted but hardened.
    if (entry === null || typeof entry !== 'object') {
      results.push({
        ipnsName: 'unknown',
        success: false,
        error: 'Invalid entry: expected a non-null object',
      });
      republishEntries.inc({ result: 'failure' });
      continue;
    }

    let ipnsPrivateKey: Uint8Array | null = null;

    try {
      // ── Step 1: Decode the marshaled IPNS record ────────────────────────────
      const signedRecordBytes = Buffer.from(entry.signedRecord, 'base64');

      // ── Step 2: Parse the record to extract value (CID) + sequence ──────────
      // Must succeed BEFORE any signature check or decryption.
      const parsed = await parseIpnsRecord(signedRecordBytes);

      // ── Step 3: Verify Ed25519 signature against publicKeyFromIpnsName ───────
      // T-67-06-T: relay cannot forge a signed record; verification PRECEDES decryption.
      // verifyIpnsRecordSignature returns false on any error — never throws.
      const isValid = await verifyIpnsRecordSignature(entry.ipnsName, signedRecordBytes);
      if (!isValid) {
        // Reject before any decryption — decrypt spy MUST be uncalled (§7.3 test 18)
        results.push({
          ipnsName: entry.ipnsName,
          success: false,
          error: 'IPNS signature verification failed',
        });
        republishEntries.inc({ result: 'failure' });
        continue;
      }

      // ── Step 4: Decrypt IPNS key using internal-epoch authority (D-03 / 67-02) ─
      const encryptedIpnsPrivateKey = new Uint8Array(
        Buffer.from(entry.encryptedIpnsPrivateKey, 'base64')
      );
      const { ipnsPrivateKey: decryptedKey, usedEpoch } = await decryptWithFallback(
        encryptedIpnsPrivateKey,
        entry.keyEpoch
      );
      ipnsPrivateKey = decryptedKey;

      // ── Step 5: Name↔key binding assertion (§6.7-2 / T-67-06-S / T-67-06-T2) ─
      // Derive the Ed25519 public key from the DECRYPTED key — NEVER from parsed.pubKey
      // (which is undefined for Ed25519 identity records — RESEARCH Pitfall 1).
      const derivedPubkey = deriveEd25519PublicKey(ipnsPrivateKey);
      const namePubkey = publicKeyFromIpnsName(entry.ipnsName);
      if (!derivedPubkey.every((b, i) => b === namePubkey[i])) {
        // Zero key before rejecting — T-67-06-I
        ipnsPrivateKey.fill(0);
        ipnsPrivateKey = null;
        results.push({
          ipnsName: entry.ipnsName,
          success: false,
          error: 'Name-key binding violation',
        });
        republishEntries.inc({ result: 'failure' });
        continue;
      }

      // ── Step 6: Re-sign — SAME value (CID) + SAME sequence + later EOL ──────
      // renewIpnsRecord parses value+sequence from the existing record internally;
      // the relay cannot inject a different CID or sequence (TEE-01 / TEE-02).
      const renewedBytes = await renewIpnsRecord(ipnsPrivateKey, signedRecordBytes);

      // ── Step 7: Epoch upgrade (T-67-06-E / D-03) ────────────────────────────
      // Target is the TEE-internal current epoch — NEVER a relay-supplied scalar.
      // Re-encrypt BEFORE zeroing so the key is still available for wrapKey.
      let upgradedEncryptedKey: string | undefined;
      let upgradedKeyEpoch: number | undefined;
      const internalCurrentEpoch = getInternalCurrentEpoch();
      if (usedEpoch !== internalCurrentEpoch) {
        const reEncrypted = await reEncryptForEpoch(ipnsPrivateKey, internalCurrentEpoch);
        upgradedEncryptedKey = Buffer.from(reEncrypted).toString('base64');
        upgradedKeyEpoch = internalCurrentEpoch;
      }

      // ── Step 8: Zero the key immediately after last use (T-67-06-I) ─────────
      ipnsPrivateKey.fill(0);
      ipnsPrivateKey = null;

      // ── Step 9: Build success result ─────────────────────────────────────────
      // newSequenceNumber == parsed.sequence (no +1) — §7.3 test 12
      const result: RepublishResult = {
        ipnsName: entry.ipnsName,
        success: true,
        signedRecord: Buffer.from(renewedBytes).toString('base64'),
        newSequenceNumber: parsed.sequence.toString(),
      };
      if (upgradedEncryptedKey) {
        result.upgradedEncryptedKey = upgradedEncryptedKey;
        result.upgradedKeyEpoch = upgradedKeyEpoch;
      }

      results.push(result);
      republishEntries.inc({ result: 'success' });
    } catch (error) {
      // Ensure key is zeroed even on unexpected error (T-67-06-I)
      if (ipnsPrivateKey) {
        ipnsPrivateKey.fill(0);
        ipnsPrivateKey = null;
      }

      // ReEnrollRequiredError → structured flag, no key material (§7.3 test 19)
      const isReEnroll = error instanceof ReEnrollRequiredError;
      const result: RepublishResult = {
        ipnsName: entry.ipnsName,
        success: false,
        error: isReEnroll
          ? 'RE_ENROLL_REQUIRED'
          : error instanceof Error
            ? error.message
            : 'Unknown error',
      };
      if (isReEnroll) {
        result.requiresReEnroll = true;
      }
      results.push(result);
      republishEntries.inc({ result: 'failure' });
    }
  }

  const successes = results.filter((r) => r.success).length;

  logger.info('Republish batch complete', {
    total: entries.length,
    succeeded: successes,
    failed: entries.length - successes,
  });

  res.json({ results });
});

export default router;
