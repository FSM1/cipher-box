import { useState, useEffect } from 'react';

/**
 * Hook that tracks navigator.onLine status with event listeners.
 * Updates reactively when browser detects network changes.
 *
 * Note: navigator.onLine only detects if network interface is connected,
 * not actual internet reachability. Handle network errors gracefully.
 */
export function useOnlineStatus(): boolean {
  const [isOnline, setIsOnline] = useState(() =>
    typeof navigator !== 'undefined' ? navigator.onLine : true
  );

  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  return isOnline;
}
