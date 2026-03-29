/**
 * Prometheus Metrics Route
 *
 * GET /metrics - Public endpoint (no auth required)
 * Returns Prometheus text format metrics for scraping.
 */

import { Router, type Request, type Response } from 'express';
import { register } from 'prom-client';

const router = Router();

router.get('/metrics', async (_req: Request, res: Response) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});

export default router;
