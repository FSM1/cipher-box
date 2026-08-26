import { Logger } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { PeriodicTask } from '../../common/worker-scheduler';
import { fakeConfig } from '../../testing/fakes';
import { AcceleratorTokenService } from '../services/accelerator-token.service';
import { AcceleratorTokenSweepTask } from './accelerator-token-sweep.task';

const DEFAULT_INTERVAL_MS = 15 * 60 * 1000;

function buildTask(env: Record<string, string | undefined>): {
  task: AcceleratorTokenSweepTask;
  sweepExpired: ReturnType<typeof vi.fn>;
} {
  const sweepExpired = vi.fn().mockResolvedValue(0);
  const acceleratorTokens = { sweepExpired } as unknown as AcceleratorTokenService;
  const task = new AcceleratorTokenSweepTask(acceleratorTokens, fakeConfig(env).service);
  return { task, sweepExpired };
}

describe('AcceleratorTokenSweepTask', () => {
  it('defaults to a 15m cadence and inherits the scheduler run bound', () => {
    const { task } = buildTask({});
    expect(task.taskName).toBe('accelerator-token-sweep');
    expect(task.intervalMs).toBe(DEFAULT_INTERVAL_MS);
    expect((task as PeriodicTask).runTimeoutMs).toBeUndefined();
  });

  it('honors a positive-integer cadence override', () => {
    const { task } = buildTask({ ACCELERATOR_TOKEN_SWEEP_INTERVAL_MS: '5000' });
    expect(task.intervalMs).toBe(5000);
  });

  it.each(['not-a-number', '0', '-1', '2147483648'])(
    'fails closed to the default cadence for %j',
    (raw) => {
      const { task } = buildTask({ ACCELERATOR_TOKEN_SWEEP_INTERVAL_MS: raw });
      expect(task.intervalMs).toBe(DEFAULT_INTERVAL_MS);
    }
  );

  it('runOnce delegates to the service sweep', async () => {
    const { task, sweepExpired } = buildTask({});
    await task.runOnce();
    expect(sweepExpired).toHaveBeenCalledOnce();
  });

  it('logs the deleted-row count so operators can see sweep activity', async () => {
    const { task, sweepExpired } = buildTask({});
    sweepExpired.mockResolvedValue(4);
    const log = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
    try {
      await task.runOnce();
      expect(log).toHaveBeenCalledWith('accelerator-token-sweep: deleted 4 expired rows');
    } finally {
      log.mockRestore();
    }
  });
});
