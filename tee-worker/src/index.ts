/**
 * CipherBox TEE Worker
 *
 * Standalone Express HTTP server for Phala Cloud CVM deployment.
 * Receives encrypted IPNS private keys, decrypts with epoch-derived keys,
 * signs IPNS records, and returns signed records.
 *
 * Routes:
 *   GET  /health      - Public health check
 *   GET  /public-key  - TEE public key per epoch (auth required)
 *   POST /republish   - Batch IPNS signing (auth required)
 */

import express from 'express';
import { authMiddleware } from './middleware/auth.js';
import healthRouter from './routes/health.js';
import publicKeyRouter from './routes/public-key.js';
import republishRouter from './routes/republish.js';

const app = express();
const port = parseInt(process.env.PORT || '3001', 10);
const mode = process.env.TEE_MODE || 'simulator';

// JSON body parsing with 10mb limit for batch requests
app.use(express.json({ limit: '10mb' }));

// Public routes (no auth)
app.use(healthRouter);

// Protected routes (auth required)
app.use(authMiddleware, publicKeyRouter);
app.use(authMiddleware, republishRouter);

app.listen(port, () => {
  console.log(`TEE Worker started on port ${port} (mode: ${mode})`);
});

export default app;
