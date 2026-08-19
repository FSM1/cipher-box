import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { positiveIntConfig } from '../../common/config-int';
import { MAX_TIMER_DELAY_MS, PeriodicTask } from '../../common/worker-scheduler';
import { DeviceApprovalService } from '../services/device-approval.service';

/**
 * Tight relative to the rendezvous TTL, so an abandoned row's sealed material is
 * gone minutes after it expires rather than whenever its account next calls;
 * via DEVICE_APPROVAL_SWEEP_INTERVAL_MS.
 */
const DEFAULT_INTERVAL_MS = 5 * 60 * 1000;

/**
 * The scheduled expiry sweep, a thin scheduling wrapper over
 * {@link DeviceApprovalService.sweepExpired}. All delete semantics, the injected
 * Clock cutoff, and batching live in the service, so the sweep is exercised
 * against real Postgres without the scheduler.
 */
@Injectable()
export class DeviceApprovalSweepTask implements PeriodicTask {
  readonly taskName = 'device-approval-sweep';
  readonly intervalMs: number;
  private readonly logger = new Logger(DeviceApprovalSweepTask.name);

  constructor(
    private readonly approvals: DeviceApprovalService,
    configService: ConfigService
  ) {
    this.intervalMs = positiveIntConfig(
      configService.get('DEVICE_APPROVAL_SWEEP_INTERVAL_MS'),
      DEFAULT_INTERVAL_MS,
      MAX_TIMER_DELAY_MS
    );
  }

  async runOnce(): Promise<void> {
    const deleted = await this.approvals.sweepExpired();
    this.logger.log(`device-approval-sweep: deleted ${deleted} expired rows`);
  }
}
