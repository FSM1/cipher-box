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

/** Current TEE epoch -- in production this would come from tee-keys state */
const TEE_EPOCH = parseInt(process.env.TEE_CURRENT_EPOCH || '1', 10);

router.post('/migrate', async (req: Request, res: Response) => {
  const { cids, sourceConfigEncrypted, destConfigEncrypted } = req.body as {
    cids?: string[];
    sourceConfigEncrypted?: string;
    destConfigEncrypted?: string;
  };

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
  if (!cids.every((c: unknown) => typeof c === 'string' && c.length > 0 && c.length <= 200)) {
    res.status(400).json({ error: 'Each CID must be a non-empty string (max 200 chars)' });
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
    const result = await migrateBatch(cids, sourceConfigEncrypted, destConfigEncrypted, TEE_EPOCH);

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

export default router;
