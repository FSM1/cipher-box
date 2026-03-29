/**
 * CipherBox TEE Worker
 *
 * Standalone Express HTTP server for Phala Cloud CVM deployment.
 * Receives encrypted IPNS private keys, decrypts with epoch-derived keys,
 * signs IPNS records, and returns signed records.
 *
 * Routes:
 *   GET  /health           - Public health check
 *   GET  /metrics          - Prometheus metrics (public, no auth)
 *   GET  /public-key       - TEE public key per epoch (auth required)
 *   POST /republish        - Batch IPNS signing (auth required)
 *   POST /migrate          - Batch CID migration between providers (auth required)
 *   POST /connection-test  - Server-side IPFS endpoint connection test (auth required)
 */

import express from 'express';
import { authMiddleware } from './middleware/auth.js';
import { metricsMiddleware } from './middleware/metrics.js';
import { logger } from './services/logger.js';
import healthRouter from './routes/health.js';
import metricsRouter from './routes/metrics.js';
import publicKeyRouter from './routes/public-key.js';
import republishRouter from './routes/republish.js';
import migrateRouter from './routes/migrate.js';
import connectionTestRouter from './routes/connection-test.js';

const app = express();
const port = parseInt(process.env.PORT || '3001', 10);
const mode = process.env.TEE_MODE || 'simulator';

// JSON body parsing with 10mb limit for batch requests
app.use(express.json({ limit: '10mb' }));

// Prometheus HTTP metrics (before route handlers, after JSON parsing)
app.use(metricsMiddleware);

// Public routes (no auth)
app.use(healthRouter);
app.use(metricsRouter);

// Protected routes (auth required)
app.use(authMiddleware, publicKeyRouter);
app.use(authMiddleware, republishRouter);
app.use(authMiddleware, migrateRouter);
app.use(authMiddleware, connectionTestRouter);

app.listen(port, () => {
  logger.info('TEE worker started', { port, mode });
});

export default app;
