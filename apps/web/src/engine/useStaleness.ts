import type { Staleness } from '@cipherbox/client';
import { useSyncExternalStore } from 'react';
import { useSnapshotStore } from '../providers/EngineProvider';

/** The staleness ladder's current rung (blueprint/web-client.md "UI state law"). */
export function useStaleness(): Staleness {
  const store = useSnapshotStore();
  return useSyncExternalStore(store.subscribe, store.getStaleness);
}
