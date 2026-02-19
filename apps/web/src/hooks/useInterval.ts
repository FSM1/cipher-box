import { useEffect, useRef } from 'react';

/**
 * Custom interval hook with proper cleanup and ref-based callback.
 * Pass null as delay to pause the interval.
 *
 * @param callback - Function to call on each interval
 * @param delay - Interval in ms, or null to pause
 */
export function useInterval(callback: () => void, delay: number | null): void {
  const savedCallback = useRef<(() => void) | null>(null);

  // Remember the latest callback without re-establishing interval
  useEffect(() => {
    savedCallback.current = callback;
  }, [callback]);

  // Set up the interval
  useEffect(() => {
    if (delay === null) return; // Pause when delay is null

    const id = setInterval(() => {
      savedCallback.current?.();
    }, delay);

    return () => clearInterval(id); // Cleanup on unmount or delay change
  }, [delay]);
}
