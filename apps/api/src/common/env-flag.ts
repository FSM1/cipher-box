/** Disabled tokens for a default-on flag; case-insensitive so `False`/`0`/`OFF` all count. */
const DISABLED_TOKENS = new Set(['false', '0', 'no', 'off']);

/** A default-on env flag is disabled only by an explicit falsey token; unset stays on. */
export function isDisabled(raw: unknown): boolean {
  return DISABLED_TOKENS.has(String(raw).trim().toLowerCase());
}
