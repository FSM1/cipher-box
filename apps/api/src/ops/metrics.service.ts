import { Injectable } from '@nestjs/common';
import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

/**
 * Prometheus metrics (blueprint/api.md Ops). Uses a per-instance registry
 * so parallel test apps never collide on metric names.
 */
@Injectable()
export class MetricsService {
  private readonly registry = new Registry();
  private readonly httpRequestsTotal: Counter<'method' | 'route' | 'status'>;
  private readonly httpRequestDurationSeconds: Histogram<'method' | 'route'>;
  private readonly republisherResolveFailuresTotal: Counter;
  private readonly republisherStaleNamesTotal: Counter;
  private readonly republisherLastWalkNames: Gauge;
  private readonly republisherLastWalkRepublished: Gauge;

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
    this.republisherResolveFailuresTotal = new Counter({
      name: 'republisher_resolve_failures_total',
      help: 'IPNS names the republisher could not resolve (orphans or unreachable)',
      registers: [this.registry],
    });
    this.republisherStaleNamesTotal = new Counter({
      name: 'republisher_stale_names_total',
      help: 'IPNS names observed >24h without a successful re-PUT',
      registers: [this.registry],
    });
    this.republisherLastWalkNames = new Gauge({
      name: 'republisher_last_walk_names',
      help: 'Distinct names walked in the most recent republisher sweep',
      registers: [this.registry],
    });
    this.republisherLastWalkRepublished = new Gauge({
      name: 'republisher_last_walk_republished',
      help: 'Names successfully re-PUT in the most recent republisher sweep',
      registers: [this.registry],
    });
  }

  observeRequest(method: string, route: string, status: number, durationSeconds: number): void {
    this.httpRequestsTotal.inc({ method, route, status: String(status) });
    this.httpRequestDurationSeconds.observe({ method, route }, durationSeconds);
  }

  observeRepublisherResolveFailure(): void {
    this.republisherResolveFailuresTotal.inc();
  }

  observeRepublisherStaleName(): void {
    this.republisherStaleNamesTotal.inc();
  }

  observeRepublisherWalk(namesWalked: number, republished: number): void {
    this.republisherLastWalkNames.set(namesWalked);
    this.republisherLastWalkRepublished.set(republished);
  }

  get contentType(): string {
    return this.registry.contentType;
  }

  metricsText(): Promise<string> {
    return this.registry.metrics();
  }
}
