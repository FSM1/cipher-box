import { Logger } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { PeriodicTask } from '../../common/worker-scheduler';
import { fakeConfig } from '../../testing/fakes';
import { DeviceApprovalService } from '../services/device-approval.service';
import { DeviceApprovalSweepTask } from './device-approval-sweep.task';

const DEFAULT_INTERVAL_MS = 5 * 60 * 1000;

function buildTask(env: Record<string, string | undefined>): {
  task: DeviceApprovalSweepTask;
  sweepExpired: ReturnType<typeof vi.fn>;
} {
  const sweepExpired = vi.fn().mockResolvedValue(0);
  const approvals = { sweepExpired } as unknown as DeviceApprovalService;
  const task = new DeviceApprovalSweepTask(approvals, fakeConfig(env).service);
  return { task, sweepExpired };
}

describe('DeviceApprovalSweepTask', () => {
  it('defaults to a 5m cadence and inherits the scheduler run bound', () => {
    const { task } = buildTask({});
    expect(task.taskName).toBe('device-approval-sweep');
    expect(task.intervalMs).toBe(DEFAULT_INTERVAL_MS);
    // No per-task timeout: the scheduler's DEFAULT_RUN_TIMEOUT_MS applies.
    expect((task as PeriodicTask).runTimeoutMs).toBeUndefined();
  });

  it('honors a positive-integer cadence override', () => {
    const { task } = buildTask({ DEVICE_APPROVAL_SWEEP_INTERVAL_MS: '5000' });
    expect(task.intervalMs).toBe(5000);
  });

  it('fails closed to the default cadence for garbage config', () => {
    const { task } = buildTask({ DEVICE_APPROVAL_SWEEP_INTERVAL_MS: 'not-a-number' });
    expect(task.intervalMs).toBe(DEFAULT_INTERVAL_MS);
  });

  it('fails closed to the default cadence for a delay above Node maximum', () => {
    const { task } = buildTask({ DEVICE_APPROVAL_SWEEP_INTERVAL_MS: '2147483648' });
    expect(task.intervalMs).toBe(DEFAULT_INTERVAL_MS);
  });

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
      expect(log).toHaveBeenCalledWith('device-approval-sweep: deleted 4 expired rows');
    } finally {
      log.mockRestore();
    }
  });
});
