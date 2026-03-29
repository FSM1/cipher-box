/**
 * Migration Route
 *
 * POST /migrate - Batch CID migration endpoint.
 *
 * Receives ECIES-encrypted provider configs and a list of CIDs to migrate.
 * Decrypts configs in-enclave, fetches encrypted blobs from source provider,
 * pins to destination provider, and verifies CID integrity.
 *
 * SECURITY:
 * - Provider credentials decrypted only inside TEE
 * - Auth tokens zeroed after migration batch completes
 * - SSRF protection on user-provided endpoint URLs
 * - No plaintext content access (opaque encrypted ciphertext)
 */

import { Router, type Request, type Response } from 'express';
import { migrateBatch } from '../services/migration-worker.js';
import { migrationCids } from '../middleware/metrics.js';
import { logger } from '../services/logger.js';

const router = Router();

router.post('/migrate', async (req: Request, res: Response) => {
  const { cids, sourceConfigEncrypted, destConfigEncrypted, currentEpoch } = req.body as {
    cids?: string[];
    sourceConfigEncrypted?: string;
    destConfigEncrypted?: string;
    currentEpoch?: number;
  };

  // Use request-provided epoch, falling back to env var
  const epoch = currentEpoch ?? parseInt(process.env.TEE_CURRENT_EPOCH || '1', 10);

  if (!cids || !Array.isArray(cids) || !sourceConfigEncrypted || !destConfigEncrypted) {
    res.status(400).json({
      error: 'Missing required fields: cids, sourceConfigEncrypted, destConfigEncrypted',
    });
    return;
  }

  // Input validation
  const MAX_BATCH_SIZE = 50;
  const MAX_CONFIG_LENGTH = 10_000; // ECIES-encrypted config is typically ~200-500 chars
  if (cids.length === 0) {
    res.status(400).json({ error: 'cids array must not be empty' });
    return;
  }
  if (cids.length > MAX_BATCH_SIZE) {
    res
      .status(400)
      .json({ error: `Batch size ${cids.length} exceeds maximum of ${MAX_BATCH_SIZE}` });
    return;
  }
  if (!cids.every((c: unknown) => typeof c === 'string' && isValidCidFormat(c as string))) {
    res.status(400).json({ error: 'Each CID must be a valid IPFS CID (CIDv0 or CIDv1)' });
    return;
  }
  if (
    sourceConfigEncrypted.length > MAX_CONFIG_LENGTH ||
    destConfigEncrypted.length > MAX_CONFIG_LENGTH
  ) {
    res
      .status(400)
      .json({ error: `Encrypted config exceeds maximum length of ${MAX_CONFIG_LENGTH}` });
    return;
  }

  try {
    const result = await migrateBatch(cids, sourceConfigEncrypted, destConfigEncrypted, epoch);

    // Increment Prometheus counters per CID result
    migrationCids.inc({ result: 'success' }, result.succeeded.length);
    migrationCids.inc({ result: 'failure' }, result.failed.length);

    // Log migration summary (NEVER log credentials or config contents)
    logger.info('Migration batch complete', {
      total: cids.length,
      succeeded: result.succeeded.length,
      failed: result.failed.length,
    });

    res.status(200).json(result);
  } catch (err) {
    logger.error('Migration batch failed', {
      error: err instanceof Error ? err.message : 'Unknown error',
    });
    res.status(500).json({
      error: err instanceof Error ? err.message : 'Migration failed',
    });
  }
});

/** Basic CID format validation (CIDv0 or CIDv1, max 200 chars) */
function isValidCidFormat(cid: string): boolean {
  if (cid.length === 0 || cid.length > 200) return false;
  // CIDv0: starts with Qm, base58btc, 46 chars
  if (/^Qm[1-9A-HJ-NP-Za-km-z]{44}$/.test(cid)) return true;
  // CIDv1: starts with b (base32) or z (base58btc) or f (base16)
  if (/^[bBzf][a-zA-Z2-7+=]+$/.test(cid)) return true;
  return false;
}

export default router;
