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
    status: 'ok',
    mode: process.env.TEE_MODE || 'simulator',
    uptime: process.uptime(),
  });
});

export default router;
