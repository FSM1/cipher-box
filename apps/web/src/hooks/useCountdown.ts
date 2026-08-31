import { useEffect, useState } from 'react';

/**
 * The time left to an ISO instant, as `m:ss`. Both halves of a device approval
 * show it: a rendezvous is short-lived, and a member who cannot see it run down
 * cannot tell a slow approver from an expired row.
 *
 * `null` where there is nothing to count, or where the instant does not parse.
 */
export function useCountdown(expiresAt: string | null): string | null {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (expiresAt === null) return;
    const millis = Date.parse(expiresAt);
    setNow(Date.now());
    if (Number.isNaN(millis)) return;
    // The reading is clamped at zero, so once the instant has passed the tick
    // only re-renders the consumer, once a second, for as long as it is mounted.
    const tick = setInterval(() => {
      const at = Date.now();
      setNow(at);
      if (at >= millis) clearInterval(tick);
    }, 1000);
    return () => clearInterval(tick);
  }, [expiresAt]);

  if (expiresAt === null) return null;
  const millis = Date.parse(expiresAt);
  if (Number.isNaN(millis)) return null;
  const left = Math.max(0, Math.floor((millis - now) / 1000));
  return `${String(Math.floor(left / 60))}:${String(left % 60).padStart(2, '0')}`;
}
