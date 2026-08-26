import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { positiveIntConfig } from '../../common/config-int';
import { MAX_TIMER_DELAY_MS, PeriodicTask } from '../../common/worker-scheduler';
import { AcceleratorTokenService } from '../services/accelerator-token.service';

/**
 * Loose relative to the pseudonym's TTL: an expired row is an opaque hash of a
 * credential that already stopped verifying, so reclaiming it within a few
 * lifetimes is enough; via ACCELERATOR_TOKEN_SWEEP_INTERVAL_MS.
 */
const DEFAULT_INTERVAL_MS = 15 * 60 * 1000;

/**
 * A wedged sweep holds a pooled connection until it is abandoned, so the bound
 * is a fraction of the cadence rather than the scheduler's hour-long default.
 */
const RUN_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * The scheduled expiry sweep, a thin scheduling wrapper over
 * {@link AcceleratorTokenService.sweepExpired}. All delete semantics, the injected
 * Clock cutoff, and batching live in the service, so the sweep is exercised
 * against real Postgres without the scheduler.
 */
@Injectable()
export class AcceleratorTokenSweepTask implements PeriodicTask {
  readonly taskName = 'accelerator-token-sweep';
  readonly intervalMs: number;
  readonly runTimeoutMs = RUN_TIMEOUT_MS;
  private readonly logger = new Logger(AcceleratorTokenSweepTask.name);

  constructor(
    private readonly acceleratorTokens: AcceleratorTokenService,
    configService: ConfigService
  ) {
    this.intervalMs = positiveIntConfig(
      configService.get('ACCELERATOR_TOKEN_SWEEP_INTERVAL_MS'),
      DEFAULT_INTERVAL_MS,
      MAX_TIMER_DELAY_MS
    );
  }

  async runOnce(): Promise<void> {
    const deleted = await this.acceleratorTokens.sweepExpired();
    this.logger.log(`accelerator-token-sweep: deleted ${deleted} expired rows`);
  }
}
