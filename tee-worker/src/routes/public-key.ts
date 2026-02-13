/**
 * Public Key Route
 *
 * GET /public-key?epoch=N - Returns the TEE public key for a given epoch.
 * Protected by auth middleware.
 */

import { Router, type Request, type Response } from 'express';
import { getKeypair } from '../services/tee-keys.js';

const router = Router();

router.get('/public-key', async (req: Request, res: Response) => {
  const epochStr = req.query.epoch as string | undefined;

  if (!epochStr || isNaN(Number(epochStr))) {
    res.status(400).json({ error: 'Missing or invalid epoch query parameter' });
    return;
  }

  const epoch = parseInt(epochStr, 10);

  try {
    const { publicKey } = await getKeypair(epoch);

    // Return hex-encoded uncompressed public key (65 bytes = 130 hex chars)
    const publicKeyHex = Buffer.from(publicKey).toString('hex');

    res.json({
      epoch,
      publicKey: publicKeyHex,
    });
  } catch (error) {
    console.error(`Failed to derive key for epoch ${epoch}:`, (error as Error).message);
    res.status(500).json({ error: 'Key derivation failed' });
  }
});

export default router;
