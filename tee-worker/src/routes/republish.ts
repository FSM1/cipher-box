/**
 * Republish Route - Stub
 *
 * POST /republish - Batch IPNS signing endpoint.
 * Full implementation in Task 2.
 */

import { Router, type Request, type Response } from 'express';

const router = Router();

router.post('/republish', (_req: Request, res: Response) => {
  res.status(501).json({ error: 'Not yet implemented' });
});

export default router;
