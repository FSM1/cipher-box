import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { positiveIntConfig } from '../../common/config-int';
import { PeriodicTask } from '../../common/worker-scheduler';
import { MailboxService } from '../services/mailbox.service';

/** ~12h cadence, a sibling of the republisher walk; via MAILBOX_SWEEP_INTERVAL_MS. */
const DEFAULT_INTERVAL_MS = 12 * 60 * 60 * 1000;
/** Hard bound on one sweep run (below the cadence); via MAILBOX_SWEEP_RUN_TIMEOUT_MS. */
const DEFAULT_RUN_TIMEOUT_MS = 60 * 60 * 1000;

/**
 * The scheduled dormant-mailbox TTL sweep (#667), shaped as a reusable
 * {@link PeriodicTask} on the shared worker loop. It is a thin scheduling wrapper
 * over {@link MailboxService.sweepExpired} — all delete semantics, the injected
 * Clock cutoff, and batching live in the service, so the sweep is exercised
 * directly against real Postgres without the scheduler. The scheduler's in-flight
 * guard makes the run single-flight in-process.
 */
@Injectable()
export class MailboxSweepTask implements PeriodicTask {
  readonly taskName = 'mailbox-sweep';
  readonly intervalMs: number;
  readonly runTimeoutMs: number;

  constructor(
    private readonly mailbox: MailboxService,
    configService: ConfigService
  ) {
    this.intervalMs = positiveIntConfig(
      configService.get('MAILBOX_SWEEP_INTERVAL_MS'),
      DEFAULT_INTERVAL_MS
    );
    this.runTimeoutMs = positiveIntConfig(
      configService.get('MAILBOX_SWEEP_RUN_TIMEOUT_MS'),
      DEFAULT_RUN_TIMEOUT_MS
    );
  }

  async runOnce(): Promise<void> {
    await this.mailbox.sweepExpired();
  }
}
