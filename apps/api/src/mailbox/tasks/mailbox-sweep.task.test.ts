import { Logger } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { PeriodicTask } from '../../common/worker-scheduler';
import { fakeConfig } from '../../testing/fakes';
import { MailboxService } from '../services/mailbox.service';
import { MailboxSweepTask } from './mailbox-sweep.task';

function buildTask(env: Record<string, string | undefined>): {
  task: MailboxSweepTask;
  sweepExpired: ReturnType<typeof vi.fn>;
} {
  const sweepExpired = vi.fn().mockResolvedValue(0);
  const mailbox = { sweepExpired } as unknown as MailboxService;
  const task = new MailboxSweepTask(mailbox, fakeConfig(env).service);
  return { task, sweepExpired };
}

describe('MailboxSweepTask', () => {
  it('defaults to a ~12h cadence and inherits the scheduler run bound', () => {
    const { task } = buildTask({});
    expect(task.taskName).toBe('mailbox-sweep');
    expect(task.intervalMs).toBe(12 * 60 * 60 * 1000);
    // No per-task timeout: the scheduler's DEFAULT_RUN_TIMEOUT_MS applies.
    expect((task as PeriodicTask).runTimeoutMs).toBeUndefined();
  });

  it('honors a positive-integer cadence override', () => {
    const { task } = buildTask({ MAILBOX_SWEEP_INTERVAL_MS: '5000' });
    expect(task.intervalMs).toBe(5000);
  });

  it('fails closed to the default cadence for garbage config', () => {
    const { task } = buildTask({ MAILBOX_SWEEP_INTERVAL_MS: 'not-a-number' });
    expect(task.intervalMs).toBe(12 * 60 * 60 * 1000);
  });

  it('runOnce delegates to the service sweep', async () => {
    const { task, sweepExpired } = buildTask({});
    await task.runOnce();
    expect(sweepExpired).toHaveBeenCalledOnce();
  });

  it('logs the deleted-row count so operators can see sweep activity', async () => {
    const { task, sweepExpired } = buildTask({});
    sweepExpired.mockResolvedValue(7);
    const log = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
    try {
      await task.runOnce();
      expect(log).toHaveBeenCalledWith('mailbox-sweep: deleted 7 expired rows');
    } finally {
      log.mockRestore();
    }
  });
});
