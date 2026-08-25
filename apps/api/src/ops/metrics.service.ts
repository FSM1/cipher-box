import { Injectable, Logger } from '@nestjs/common';
import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

/** The outcome axis shared by the auth and gateway-verify counters. */
export type AuthOutcome = 'success' | 'rejected' | 'error';

/**
 * Prometheus metrics (blueprint/api.md Ops). Uses a per-instance registry
 * so parallel test apps never collide on metric names.
 */
@Injectable()
export class MetricsService {
  private readonly logger = new Logger(MetricsService.name);
  private readonly registry = new Registry();
  private readonly httpRequestsTotal: Counter<'method' | 'route' | 'status'>;
  private readonly httpRequestDurationSeconds: Histogram<'method' | 'route'>;
  private readonly republisherResolveFailuresTotal: Counter;
  private readonly republisherStaleNamesTotal: Counter;
  private readonly republisherLastWalkNames: Gauge;
  private readonly republisherLastWalkRepublished: Gauge;
  private readonly republisherWalksSkippedTotal: Counter;
  private readonly mailboxPendingMessages: Gauge;
  private readonly mailboxPendingCapRejectionsTotal: Counter;
  private readonly authAttemptsTotal: Counter<'route' | 'outcome'>;
  private readonly throttleRejectionsTotal: Counter<'route'>;
  private readonly gatewayVerifyTotal: Counter<'outcome'>;
  private mailboxDepthSample?: () => Promise<number>;

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
    // A counter, not a "configured" gauge: an unset gauge reads 0, so a
    // correctly configured deploy would report itself unconfigured until its
    // first sweep, a cadence away.
    this.republisherWalksSkippedTotal = new Counter({
      name: 'republisher_walks_skipped_total',
      help: 'Republisher sweeps that skipped the walk because no routing endpoint is configured',
      registers: [this.registry],
    });
    this.mailboxPendingMessages = new Gauge({
      name: 'mailbox_pending_messages',
      help: 'Undelivered mailbox messages across all recipients',
      registers: [this.registry],
      collect: async () => {
        if (!this.mailboxDepthSample) {
          return;
        }
        try {
          this.mailboxPendingMessages.set(await this.mailboxDepthSample());
        } catch (error) {
          // A sampler fault must not fail the whole scrape: the gauge keeps its
          // last value and every other series is still served.
          this.logger.warn(`mailbox depth sample failed: ${String(error)}`);
        }
      },
    });
    this.mailboxPendingCapRejectionsTotal = new Counter({
      name: 'mailbox_pending_cap_rejections_total',
      help: 'Mailbox posts refused because the recipient is at the pending cap',
      registers: [this.registry],
    });
    // Labelled by route, never by account or credential: a metric label is a
    // permanent, unauthenticated read on /metrics.
    this.authAttemptsTotal = new Counter({
      name: 'auth_attempts_total',
      help: 'Auth surface attempts, by route and outcome',
      labelNames: ['route', 'outcome'],
      registers: [this.registry],
    });
    this.throttleRejectionsTotal = new Counter({
      name: 'throttle_rejections_total',
      help: 'Requests refused with 429 by the global throttler, by route',
      labelNames: ['route'],
      registers: [this.registry],
    });
    this.gatewayVerifyTotal = new Counter({
      name: 'gateway_verify_total',
      help: 'Read accelerator token verifications for the gateway front, by outcome',
      labelNames: ['outcome'],
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

  observeRepublisherWalkSkipped(): void {
    this.republisherWalksSkippedTotal.inc();
  }

  /**
   * Bind the mailbox depth to a sampler read at scrape time. Pushing it from
   * the write paths would leave the gauge frozen between posts, which is
   * exactly the quiet backlog the panel exists to show.
   */
  sampleMailboxPendingDepth(sample: () => Promise<number>): void {
    this.mailboxDepthSample = sample;
  }

  observeMailboxPendingCapRejection(): void {
    this.mailboxPendingCapRejectionsTotal.inc();
  }

  observeAuthAttempt(route: string, outcome: AuthOutcome): void {
    this.authAttemptsTotal.inc({ route, outcome });
  }

  observeThrottleRejection(route: string): void {
    this.throttleRejectionsTotal.inc({ route });
  }

  observeGatewayVerify(outcome: 'accepted' | 'refused'): void {
    this.gatewayVerifyTotal.inc({ outcome });
  }

  get contentType(): string {
    return this.registry.contentType;
  }

  metricsText(): Promise<string> {
    return this.registry.metrics();
  }
}
