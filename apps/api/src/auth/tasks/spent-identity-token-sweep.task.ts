import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { positiveIntConfig } from '../../common/config-int';
import { MAX_TIMER_DELAY_MS, PeriodicTask } from '../../common/worker-scheduler';
import { IdentityTokenService } from '../services/identity-token.service';

/**
 * A spent row past its grace refuses nothing, as its token no longer verifies,
 * so reclaiming it within a few token lifetimes is enough; via
 * SPENT_IDENTITY_TOKEN_SWEEP_INTERVAL_MS.
 */
const DEFAULT_INTERVAL_MS = 15 * 60 * 1000;

/**
 * A wedged sweep holds a pooled connection until it is abandoned, so the bound
 * is a fraction of the cadence rather than the scheduler's hour-long default.
 */
const RUN_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * The scheduled spent-row sweep, a thin scheduling wrapper over
 * {@link IdentityTokenService.sweepExpired}, where the cutoff and the batching
 * live.
 */
@Injectable()
export class SpentIdentityTokenSweepTask implements PeriodicTask {
  readonly taskName = 'spent-identity-token-sweep';
  readonly intervalMs: number;
  readonly runTimeoutMs = RUN_TIMEOUT_MS;
  private readonly logger = new Logger(SpentIdentityTokenSweepTask.name);

  constructor(
    private readonly identityTokens: IdentityTokenService,
    configService: ConfigService
  ) {
    this.intervalMs = positiveIntConfig(
      configService.get('SPENT_IDENTITY_TOKEN_SWEEP_INTERVAL_MS'),
      DEFAULT_INTERVAL_MS,
      MAX_TIMER_DELAY_MS
    );
  }

  async runOnce(): Promise<void> {
    const deleted = await this.identityTokens.sweepExpired();
    this.logger.log(`spent-identity-token-sweep: deleted ${deleted} expired rows`);
  }
}
