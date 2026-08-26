import { Logger } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { PeriodicTask } from '../../common/worker-scheduler';
import { fakeConfig } from '../../testing/fakes';
import { GatewayTokenService } from '../services/gateway-token.service';
import { GatewayTokenSweepTask } from './gateway-token-sweep.task';

const DEFAULT_INTERVAL_MS = 15 * 60 * 1000;

function buildTask(env: Record<string, string | undefined>): {
  task: GatewayTokenSweepTask;
  sweepExpired: ReturnType<typeof vi.fn>;
} {
  const sweepExpired = vi.fn().mockResolvedValue(0);
  const gatewayTokens = { sweepExpired } as unknown as GatewayTokenService;
  const task = new GatewayTokenSweepTask(gatewayTokens, fakeConfig(env).service);
  return { task, sweepExpired };
}

describe('GatewayTokenSweepTask', () => {
  it('defaults to a 15m cadence and inherits the scheduler run bound', () => {
    const { task } = buildTask({});
    expect(task.taskName).toBe('gateway-token-sweep');
    expect(task.intervalMs).toBe(DEFAULT_INTERVAL_MS);
    expect((task as PeriodicTask).runTimeoutMs).toBeUndefined();
  });

  it('honors a positive-integer cadence override', () => {
    const { task } = buildTask({ GATEWAY_TOKEN_SWEEP_INTERVAL_MS: '5000' });
    expect(task.intervalMs).toBe(5000);
  });

  it.each(['not-a-number', '0', '-1', '2147483648'])(
    'fails closed to the default cadence for %j',
    (raw) => {
      const { task } = buildTask({ GATEWAY_TOKEN_SWEEP_INTERVAL_MS: raw });
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
      expect(log).toHaveBeenCalledWith('gateway-token-sweep: deleted 4 expired rows');
    } finally {
      log.mockRestore();
    }
  });
});
