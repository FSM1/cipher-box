import { useSyncExternalStore } from 'react';
import { useSnapshotStore } from '../providers/EngineProvider';
import type { SnapshotState } from './snapshotStore';

/** The focused folder as the engine last reported it. */
export function useSnapshot(): SnapshotState {
  const store = useSnapshotStore();
  return useSyncExternalStore(store.subscribe, store.getSnapshot);
}
