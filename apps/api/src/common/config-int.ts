/**
 * Read a positive-integer bound from config, failing closed to `fallback` for an
 * unset OR garbage value. A misconfigured env var must never silently become
 * `NaN` (which would disable the bound it controls), so the guard is `> 0` AND
 * integral — the shared parse for every DoS/efficiency knob.
 */
export function positiveIntConfig(raw: unknown, fallback: number): number {
  const value = Number(raw);
  return Number.isInteger(value) && value > 0 ? value : fallback;
}
