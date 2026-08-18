import { describe, expect, it } from 'vitest';
import { MetricsService } from '../ops/metrics.service';
import { LoggingRepublisherAlerter } from './republisher.alerter';

/** Read a single unlabelled Prometheus sample out of the exposition text. */
function sample(text: string, name: string): number | null {
  const match = new RegExp(`^${name} (-?[0-9.e+]+)$`, 'm').exec(text);
  return match ? Number(match[1]) : null;
}

describe('LoggingRepublisherAlerter walk signals', () => {
  it('reports the republisher as unconfigured after a skipped walk', async () => {
    const metrics = new MetricsService();
    new LoggingRepublisherAlerter(metrics).walkSkipped();

    const text = await metrics.metricsText();
    expect(sample(text, 'republisher_configured')).toBe(0);
  });

  it('distinguishes a configured sweep with nothing to do from a skipped walk', async () => {
    const metrics = new MetricsService();
    const alerter = new LoggingRepublisherAlerter(metrics);

    alerter.walkSkipped();
    alerter.walkComplete(0, 0);

    const text = await metrics.metricsText();
    expect(sample(text, 'republisher_configured')).toBe(1);
    expect(sample(text, 'republisher_last_walk_names')).toBe(0);
    expect(sample(text, 'republisher_last_walk_republished')).toBe(0);
  });
});
