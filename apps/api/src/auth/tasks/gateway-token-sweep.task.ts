import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { positiveIntConfig } from '../../common/config-int';
import { MAX_TIMER_DELAY_MS, PeriodicTask } from '../../common/worker-scheduler';
import { GatewayTokenService } from '../services/gateway-token.service';

/**
 * Loose relative to the pseudonym's TTL: an expired row is an opaque hash of a
 * credential that already stopped verifying, so reclaiming it within a few
 * lifetimes is enough; via GATEWAY_TOKEN_SWEEP_INTERVAL_MS.
 */
const DEFAULT_INTERVAL_MS = 15 * 60 * 1000;

/**
 * The scheduled expiry sweep, a thin scheduling wrapper over
 * {@link GatewayTokenService.sweepExpired}. All delete semantics, the injected
 * Clock cutoff, and batching live in the service, so the sweep is exercised
 * against real Postgres without the scheduler.
 */
@Injectable()
export class GatewayTokenSweepTask implements PeriodicTask {
  readonly taskName = 'gateway-token-sweep';
  readonly intervalMs: number;
  private readonly logger = new Logger(GatewayTokenSweepTask.name);

  constructor(
    private readonly gatewayTokens: GatewayTokenService,
    configService: ConfigService
  ) {
    this.intervalMs = positiveIntConfig(
      configService.get('GATEWAY_TOKEN_SWEEP_INTERVAL_MS'),
      DEFAULT_INTERVAL_MS,
      MAX_TIMER_DELAY_MS
    );
  }

  async runOnce(): Promise<void> {
    const deleted = await this.gatewayTokens.sweepExpired();
    this.logger.log(`gateway-token-sweep: deleted ${deleted} expired rows`);
  }
}
