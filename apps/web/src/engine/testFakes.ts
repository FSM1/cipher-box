/**
 * The engine as the adapter sees it: an event stream plus a `snapshot` the test
 * settles by hand, so pull ordering is observable rather than timing-dependent.
 */

import type {
  EngineClient,
  EventDescriptor,
  SnapshotDescriptor,
  Staleness,
} from '@cipherbox/client';

/** The anchored root id a first-run vault reports. */
export const ROOT_ID: Uint8Array = new Uint8Array(16);

export function view(
  folder: Uint8Array = ROOT_ID,
  staleness: Staleness = 'fresh',
  children = 0
): SnapshotDescriptor {
  return {
    root: ROOT_ID,
    folder,
    folderName: '',
    children: Array.from({ length: children }, (_, i) => ({
      id: new Uint8Array(16).fill(i + 1),
      name: `child-${i}`,
      kind: 'file',
      size: null,
      mtime: null,
      pending: 'none',
      deadLetter: false,
      contentVersion: null,
    })),
    ancestors: [],
    deadLetters: [],
    blocked: null,
    retainedRecords: 0,
    staleness,
  };
}

interface Pull {
  /** The folder asked for, or `null` for "whatever the engine's root is". */
  folder: Uint8Array | null;
  resolve: (view: SnapshotDescriptor) => void;
  reject: (error: Error) => void;
}

export function fakeEngine() {
  const listeners = new Set<(event: EventDescriptor) => void>();
  const pulls: Pull[] = [];
  const focus: (Uint8Array | null)[] = [];
  const reported: (Uint8Array | null)[] = [];
  let settleFocus: (() => void) | null = null;
  let failFocus: ((error: Error) => void) | null = null;
  let refreshes = 0;

  const client = {
    facade: {
      subscribe(listener: (event: EventDescriptor) => void) {
        listeners.add(listener);
        return () => listeners.delete(listener);
      },
      snapshot(folder: Uint8Array | null) {
        return new Promise<SnapshotDescriptor>((resolve, reject) => {
          pulls.push({ folder, resolve, reject });
        });
      },
      setFocus(node: Uint8Array | null) {
        focus.push(node);
        return new Promise<void>((resolve, reject) => {
          settleFocus = resolve;
          failFocus = reject;
        });
      },
      manualRefresh() {
        refreshes += 1;
        return Promise.resolve();
      },
    },
    reportFocus(node: Uint8Array | null) {
      reported.push(node);
    },
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;

  return {
    client,
    pulls,
    focus,
    reported,
    emit: (event: EventDescriptor) => {
      for (const listener of listeners) listener(event);
    },
    ackFocus: () => settleFocus?.(),
    rejectFocus: (error: Error) => failFocus?.(error),
    refreshes: () => refreshes,
    subscriberCount: () => listeners.size,
  };
}

/** Lets every pending promise callback in the store run. */
export const flush = (): Promise<unknown> => new Promise((resolve) => setTimeout(resolve, 0));
