import { useEffect, useRef } from 'react';
import { useOnlineStatus } from '../hooks/useOnlineStatus';
import { useVisibility } from '../hooks/useVisibility';
import { useSnapshotStore } from '../providers/EngineProvider';

/**
 * Regaining the network or coming back to a backgrounded tab are the two moments
 * a cached vault is most likely behind, so each edge back into
 * on-screen-and-online drives one nocache refresh — the transition only, never
 * the mount.
 */
export function useRefreshOnWake(): void {
  const store = useSnapshotStore();
  const online = useOnlineStatus();
  const visible = useVisibility();
  const wasReady = useRef(true);

  useEffect(() => {
    const ready = online && visible;
    if (ready && !wasReady.current) store.refresh();
    wasReady.current = ready;
  }, [online, visible, store]);
}
