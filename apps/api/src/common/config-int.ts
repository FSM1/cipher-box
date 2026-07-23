/**
 * Read a positive-integer bound from config, failing closed to `fallback` for an
 * unset OR garbage value. A misconfigured env var must never silently become
 * `NaN` (which would disable the bound it controls), so the guard is `> 0` AND
 * integral — the shared parse for every DoS/efficiency knob.
 *
 * `max` fails closed the same way for an out-of-range value: a timer delay above
 * Node's max (see MAX_TIMER_DELAY_MS) is coerced to 1ms, so an over-range cadence
 * would otherwise run near-continuously.
 */
export function positiveIntConfig(raw: unknown, fallback: number, max?: number): number {
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    return fallback;
  }
  return max !== undefined && value > max ? fallback : value;
}
