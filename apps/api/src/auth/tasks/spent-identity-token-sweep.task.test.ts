import { Logger } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { PeriodicTask } from '../../common/worker-scheduler';
import { fakeConfig } from '../../testing/fakes';
import { IdentityTokenService } from '../services/identity-token.service';
import { SpentIdentityTokenSweepTask } from './spent-identity-token-sweep.task';

const DEFAULT_INTERVAL_MS = 15 * 60 * 1000;

function buildTask(env: Record<string, string | undefined>): {
  task: SpentIdentityTokenSweepTask;
  sweepExpired: ReturnType<typeof vi.fn>;
} {
  const sweepExpired = vi.fn().mockResolvedValue(0);
  const identityTokens = { sweepExpired } as unknown as IdentityTokenService;
  const task = new SpentIdentityTokenSweepTask(identityTokens, fakeConfig(env).service);
  return { task, sweepExpired };
}

describe('SpentIdentityTokenSweepTask', () => {
  it('defaults to a 15-minute cadence and bounds a run well inside it', () => {
    const { task } = buildTask({});
    expect(task.taskName).toBe('spent-identity-token-sweep');
    expect(task.intervalMs).toBe(DEFAULT_INTERVAL_MS);
    expect((task as PeriodicTask).runTimeoutMs).toBeLessThan(DEFAULT_INTERVAL_MS);
  });

  it('honors a positive-integer cadence override', () => {
    const { task } = buildTask({ SPENT_IDENTITY_TOKEN_SWEEP_INTERVAL_MS: '5000' });
    expect(task.intervalMs).toBe(5000);
  });

  it.each(['not-a-number', '0', '-1', '2147483648'])(
    'fails closed to the default cadence for %j',
    (raw) => {
      const { task } = buildTask({ SPENT_IDENTITY_TOKEN_SWEEP_INTERVAL_MS: raw });
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
      expect(log).toHaveBeenCalledWith('spent-identity-token-sweep: deleted 4 expired rows');
    } finally {
      log.mockRestore();
    }
  });
});
