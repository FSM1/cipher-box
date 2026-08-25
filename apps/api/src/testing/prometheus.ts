/**
 * One unlabelled series out of a Prometheus text exposition; null when the
 * series is absent, so a mistyped metric name can never read as a real zero.
 */
export function sampleMetric(text: string, name: string): number | null {
  const match = new RegExp(`^${name} (\\S+)$`, 'm').exec(text);
  return match ? Number(match[1]) : null;
}
