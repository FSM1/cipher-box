/**
 * Prometheus HTTP metrics middleware for Express.
 *
 * Mirrors the API's cipherbox_http_request_duration_seconds pattern
 * with a tee-specific prefix for Grafana dashboard compatibility.
 * Both API and TEE worker metrics can coexist on the same dashboard.
 */

import { Histogram, Counter } from 'prom-client';
import type { Request, Response, NextFunction } from 'express';

/** HTTP request duration histogram with method/route/status_code labels */
const httpDuration = new Histogram({
  name: 'cipherbox_tee_http_request_duration_seconds',
  help: 'TEE worker HTTP request duration in seconds',
  labelNames: ['method', 'route', 'status_code'] as const,
  buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
});

/** Total IPNS entries processed by TEE republish */
export const republishEntries = new Counter({
  name: 'cipherbox_tee_republish_entries_total',
  help: 'Total IPNS entries processed by TEE republish',
  labelNames: ['result'] as const, // 'success' | 'failure'
});

/** Total CIDs processed by TEE migration */
export const migrationCids = new Counter({
  name: 'cipherbox_tee_migration_cids_total',
  help: 'Total CIDs processed by TEE migration',
  labelNames: ['result'] as const, // 'success' | 'failure'
});

/**
 * Express middleware that records HTTP request duration as a Prometheus histogram.
 * Skips instrumentation for the /metrics endpoint itself to avoid self-referential noise.
 */
export function metricsMiddleware(req: Request, res: Response, next: NextFunction): void {
  if (req.path === '/metrics') {
    next();
    return;
  }

  const start = process.hrtime.bigint();

  res.on('finish', () => {
    const durationNs = Number(process.hrtime.bigint() - start);
    const route = req.route?.path ?? 'unmatched';
    httpDuration.observe(
      { method: req.method, route, status_code: res.statusCode },
      durationNs / 1e9
    );
  });

  next();
}
