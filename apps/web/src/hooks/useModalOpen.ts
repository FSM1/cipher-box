import { useSyncExternalStore } from 'react';

/**
 * Lightweight global counter for open modals.
 * Used to pause the app-level MatrixBackground when a modal is showing
 * its own dedicated matrix animation.
 */
let openCount = 0;
const listeners = new Set<() => void>();

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function getSnapshot() {
  return openCount > 0;
}

export function incrementModalCount() {
  openCount++;
  listeners.forEach((l) => {
    l();
  });
}

export function decrementModalCount() {
  openCount = Math.max(0, openCount - 1);
  listeners.forEach((l) => {
    l();
  });
}

/** Returns true when any modal is open */
export function useAnyModalOpen(): boolean {
  return useSyncExternalStore(subscribe, getSnapshot);
}
