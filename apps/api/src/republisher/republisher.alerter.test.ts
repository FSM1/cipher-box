import { describe, expect, it } from 'vitest';
import { MetricsService } from '../ops/metrics.service';
import { LoggingRepublisherAlerter } from './republisher.alerter';

/** Read one unlabelled Prometheus sample out of the exposition text. */
function sample(text: string, name: string): number | null {
  const match = new RegExp(`^${name} (\\S+)$`, 'm').exec(text);
  return match ? Number(match[1]) : null;
}

describe('LoggingRepublisherAlerter walk signals', () => {
  it('counts a skipped walk apart from the sweeps that walked', async () => {
    const metrics = new MetricsService();
    const alerter = new LoggingRepublisherAlerter(metrics);

    alerter.walkComplete(4, 4);
    expect(sample(await metrics.metricsText(), 'republisher_walks_skipped_total')).toBe(0);

    alerter.walkSkipped();
    expect(sample(await metrics.metricsText(), 'republisher_walks_skipped_total')).toBe(1);
  });

  it('distinguishes a configured sweep with nothing to do from a skipped walk', async () => {
    const metrics = new MetricsService();
    const alerter = new LoggingRepublisherAlerter(metrics);

    // The empty-inventory sweep the skip signal must not be confused with.
    alerter.walkComplete(0, 0);

    const text = await metrics.metricsText();
    expect(sample(text, 'republisher_last_walk_names')).toBe(0);
    expect(sample(text, 'republisher_walks_skipped_total')).toBe(0);
  });
});
