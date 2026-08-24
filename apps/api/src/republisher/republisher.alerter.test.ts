import { Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { MetricsService } from '../ops/metrics.service';
import { sampleMetric } from '../testing/prometheus';
import { LoggingRepublisherAlerter } from './republisher.alerter';

describe('LoggingRepublisherAlerter walk signals', () => {
  let warnSpy: MockInstance<Logger['warn']>;

  beforeEach(() => {
    warnSpy = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('counts a skipped walk apart from the sweeps that walked', async () => {
    const metrics = new MetricsService();
    const alerter = new LoggingRepublisherAlerter(metrics);

    alerter.walkComplete(4, 4);
    expect(sampleMetric(await metrics.metricsText(), 'republisher_walks_skipped_total')).toBe(0);

    alerter.walkSkipped();
    expect(sampleMetric(await metrics.metricsText(), 'republisher_walks_skipped_total')).toBe(1);
  });

  // One warning per sweep, never one per name: that is what keeps a BYO-only
  // deploy from paging on every registered name it could not walk.
  it('warns exactly once for a skipped walk', () => {
    const alerter = new LoggingRepublisherAlerter(new MetricsService());

    alerter.walkSkipped();

    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('no routing endpoint'));
  });

  it('distinguishes a configured sweep with nothing to do from a skipped walk', async () => {
    const metrics = new MetricsService();
    const alerter = new LoggingRepublisherAlerter(metrics);

    // The empty-inventory sweep the skip signal must not be confused with.
    alerter.walkComplete(0, 0);

    const text = await metrics.metricsText();
    expect(sampleMetric(text, 'republisher_last_walk_names')).toBe(0);
    expect(sampleMetric(text, 'republisher_walks_skipped_total')).toBe(0);
    expect(warnSpy).not.toHaveBeenCalled();
  });
});
