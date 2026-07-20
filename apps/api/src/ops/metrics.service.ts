import { Injectable } from '@nestjs/common';
import { Counter, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

/**
 * Prometheus metrics (blueprint/api.md Ops). Uses a per-instance registry
 * so parallel test apps never collide on metric names.
 */
@Injectable()
export class MetricsService {
  private readonly registry = new Registry();
  private readonly httpRequestsTotal: Counter<'method' | 'route' | 'status'>;
  private readonly httpRequestDurationSeconds: Histogram<'method' | 'route'>;

  constructor() {
    collectDefaultMetrics({ register: this.registry });
    this.httpRequestsTotal = new Counter({
      name: 'http_requests_total',
      help: 'Total HTTP requests handled, by method, route, and status code',
      labelNames: ['method', 'route', 'status'],
      registers: [this.registry],
    });
    this.httpRequestDurationSeconds = new Histogram({
      name: 'http_request_duration_seconds',
      help: 'HTTP request duration in seconds, by method and route',
      labelNames: ['method', 'route'],
      registers: [this.registry],
    });
  }

  observeRequest(method: string, route: string, status: number, durationSeconds: number): void {
    this.httpRequestsTotal.inc({ method, route, status: String(status) });
    this.httpRequestDurationSeconds.observe({ method, route }, durationSeconds);
  }

  get contentType(): string {
    return this.registry.contentType;
  }

  metricsText(): Promise<string> {
    return this.registry.metrics();
  }
}
