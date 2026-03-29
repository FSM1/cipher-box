/**
 * Public Key Route
 *
 * GET /public-key?epoch=N - Returns the TEE public key for a given epoch.
 * Protected by auth middleware.
 */

import { Router, type Request, type Response } from 'express';
import { getPublicKey, MIN_EPOCH, MAX_EPOCH } from '../services/tee-keys.js';
import { logger } from '../services/logger.js';

const router = Router();

router.get('/public-key', async (req: Request, res: Response) => {
  const epochStr = req.query.epoch as string | undefined;

  if (!epochStr || isNaN(Number(epochStr))) {
    res.status(400).json({ error: 'Missing or invalid epoch query parameter' });
    return;
  }

  const epoch = parseInt(epochStr, 10);

  if (!Number.isInteger(epoch) || epoch < MIN_EPOCH || epoch > MAX_EPOCH) {
    res
      .status(400)
      .json({ error: `Epoch must be an integer between ${MIN_EPOCH} and ${MAX_EPOCH}` });
    return;
  }

  try {
    const publicKey = await getPublicKey(epoch);
    const publicKeyHex = Buffer.from(publicKey).toString('hex');

    res.json({
      epoch,
      publicKey: publicKeyHex,
    });
  } catch (error) {
    logger.error('Key derivation failed', { epoch, error: (error as Error).message });
    res.status(500).json({ error: 'Key derivation failed' });
  }
});

export default router;
