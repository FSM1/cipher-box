/**
 * Health Check Route
 *
 * GET /health - Public endpoint (no auth required)
 * Returns worker status, mode, and uptime.
 */

import { Router, type Request, type Response } from 'express';

const router = Router();

router.get('/health', (_req: Request, res: Response) => {
  res.json({
    healthy: true,
    mode: process.env.TEE_MODE || 'simulator',
    epoch: parseInt(process.env.TEE_EPOCH || '1', 10),
    uptime: process.uptime(),
  });
});

export default router;
