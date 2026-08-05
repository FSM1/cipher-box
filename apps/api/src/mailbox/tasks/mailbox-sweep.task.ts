import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { positiveIntConfig } from '../../common/config-int';
import { MAX_TIMER_DELAY_MS, PeriodicTask } from '../../common/worker-scheduler';
import { MailboxService } from '../services/mailbox.service';

/** ~12h cadence, a sibling of the republisher walk; via MAILBOX_SWEEP_INTERVAL_MS. */
const DEFAULT_INTERVAL_MS = 12 * 60 * 60 * 1000;

/**
 * The scheduled dormant-mailbox TTL sweep, shaped as a reusable
 * {@link PeriodicTask} on the shared worker loop. It is a thin scheduling wrapper
 * over {@link MailboxService.sweepExpired} — all delete semantics, the injected
 * Clock cutoff, and batching live in the service, so the sweep is exercised
 * directly against real Postgres without the scheduler. The scheduler's in-flight
 * guard makes the run single-flight in-process.
 *
 * No per-run timeout is declared, so the scheduler's default applies. That
 * timeout only frees the scheduling slot on expiry — it does NOT cancel an
 * in-flight `sweepExpired`; the run self-bounds via SWEEP_MAX_BATCHES + drain
 * (each batch its own autocommit txn), so it finishes its bounded work and a
 * benign overlap with the next tick is acceptable.
 */
@Injectable()
export class MailboxSweepTask implements PeriodicTask {
  readonly taskName = 'mailbox-sweep';
  readonly intervalMs: number;
  private readonly logger = new Logger(MailboxSweepTask.name);

  constructor(
    private readonly mailbox: MailboxService,
    configService: ConfigService
  ) {
    this.intervalMs = positiveIntConfig(
      configService.get('MAILBOX_SWEEP_INTERVAL_MS'),
      DEFAULT_INTERVAL_MS,
      MAX_TIMER_DELAY_MS
    );
  }

  async runOnce(): Promise<void> {
    const deleted = await this.mailbox.sweepExpired();
    this.logger.log(`mailbox-sweep: deleted ${deleted} expired rows`);
  }
}
