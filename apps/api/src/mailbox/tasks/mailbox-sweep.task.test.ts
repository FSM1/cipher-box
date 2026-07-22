import { describe, expect, it, vi } from 'vitest';
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
  it('defaults to a ~12h cadence and a 1h run bound', () => {
    const { task } = buildTask({});
    expect(task.taskName).toBe('mailbox-sweep');
    expect(task.intervalMs).toBe(12 * 60 * 60 * 1000);
    expect(task.runTimeoutMs).toBe(60 * 60 * 1000);
  });

  it('honors positive-integer overrides', () => {
    const { task } = buildTask({
      MAILBOX_SWEEP_INTERVAL_MS: '5000',
      MAILBOX_SWEEP_RUN_TIMEOUT_MS: '2500',
    });
    expect(task.intervalMs).toBe(5000);
    expect(task.runTimeoutMs).toBe(2500);
  });

  it('fails closed to the defaults for garbage config', () => {
    const { task } = buildTask({
      MAILBOX_SWEEP_INTERVAL_MS: 'not-a-number',
      MAILBOX_SWEEP_RUN_TIMEOUT_MS: '-1',
    });
    expect(task.intervalMs).toBe(12 * 60 * 60 * 1000);
    expect(task.runTimeoutMs).toBe(60 * 60 * 1000);
  });

  it('runOnce delegates to the service sweep', async () => {
    const { task, sweepExpired } = buildTask({});
    await task.runOnce();
    expect(sweepExpired).toHaveBeenCalledOnce();
  });
});
