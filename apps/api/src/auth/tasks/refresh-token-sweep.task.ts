import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { positiveIntConfig } from '../../common/config-int';
import { MAX_TIMER_DELAY_MS, PeriodicTask } from '../../common/worker-scheduler';
import { TokenService } from '../services/token.service';

/**
 * Loose relative to the refresh token's multi-day TTL: an expired row already
 * fails the expiry check, so reclaiming it within an hour is enough; via
 * REFRESH_TOKEN_SWEEP_INTERVAL_MS.
 */
const DEFAULT_INTERVAL_MS = 60 * 60 * 1000;

/**
 * A wedged sweep holds a pooled connection until it is abandoned, so the bound
 * is a fraction of the cadence rather than the scheduler's hour-long default.
 */
const RUN_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * The scheduled expiry sweep, a thin scheduling wrapper over
 * {@link TokenService.sweepExpired}. All delete semantics, the injected Clock
 * cutoff, and batching live in the service, so the sweep is exercised against
 * real Postgres without the scheduler.
 */
@Injectable()
export class RefreshTokenSweepTask implements PeriodicTask {
  readonly taskName = 'refresh-token-sweep';
  readonly intervalMs: number;
  readonly runTimeoutMs = RUN_TIMEOUT_MS;
  private readonly logger = new Logger(RefreshTokenSweepTask.name);

  constructor(
    private readonly tokens: TokenService,
    configService: ConfigService
  ) {
    this.intervalMs = positiveIntConfig(
      configService.get('REFRESH_TOKEN_SWEEP_INTERVAL_MS'),
      DEFAULT_INTERVAL_MS,
      MAX_TIMER_DELAY_MS
    );
  }

  async runOnce(): Promise<void> {
    const deleted = await this.tokens.sweepExpired();
    this.logger.log(`refresh-token-sweep: deleted ${deleted} expired rows`);
  }
}
