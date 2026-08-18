import { Injectable, Logger } from '@nestjs/common';
import { MetricsService } from '../ops/metrics.service';

/**
 * Where the republisher raises liveness alerts (blueprint/api.md). A seam so the
 * walk stays deterministic and testable: tests inject a recording fake and
 * assert exactly which names alerted, while production logs and increments
 * Prometheus counters an operator can page on.
 */
@Injectable()
export abstract class RepublisherAlerter {
  /** A registered name the network could not resolve — an orphan or unreachable. */
  abstract resolveFailure(ipnsName: string): void;
  /** A name >24h without a successful re-PUT — the liveness backstop is slipping. */
  abstract staleRepublish(ipnsName: string, ageMs: number): void;
  /** End-of-sweep summary for dashboards. */
  abstract walkComplete(namesWalked: number, republished: number): void;
  /**
   * The walk could not run: no routing endpoint is configured (a supported
   * BYO-only deploy), so nothing was resolved or re-PUT.
   */
  abstract walkSkipped(): void;
}

@Injectable()
export class LoggingRepublisherAlerter extends RepublisherAlerter {
  private readonly logger = new Logger(RepublisherAlerter.name);

  constructor(private readonly metrics: MetricsService) {
    super();
  }

  resolveFailure(ipnsName: string): void {
    this.metrics.observeRepublisherResolveFailure();
    this.logger.warn(`republisher resolve failure for ${ipnsName}`);
  }

  staleRepublish(ipnsName: string, ageMs: number): void {
    this.metrics.observeRepublisherStaleName();
    this.logger.warn(
      `republisher: ${ipnsName} has gone ${Math.round(ageMs / 3_600_000)}h without a successful re-PUT`
    );
  }

  walkComplete(namesWalked: number, republished: number): void {
    this.metrics.observeRepublisherWalk(namesWalked, republished);
  }

  walkSkipped(): void {
    this.metrics.observeRepublisherWalkSkipped();
    this.logger.warn('republisher walk skipped: no routing endpoint is configured');
  }
}
