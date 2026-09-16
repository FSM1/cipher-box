/**
 * The version surface of the engine, recorded: a test states what the engine
 * holds and asserts what the dialog dispatched, not how it got there.
 */

import type { ReactElement } from 'react';
import type {
  CommandOutcomeDescriptor,
  EngineClient,
  EventDescriptor,
  VersionEntryDescriptor,
} from '@cipherbox/client';
import { render } from '@testing-library/react';
import { vi } from 'vitest';
import { EngineProvider } from '../providers/EngineProvider';

const DONE: CommandOutcomeDescriptor = { kind: 'done' };

/** Which version call a test makes the engine refuse, or hold open forever. */
export type VersionCall = 'fileVersions' | 'downloadVersion' | 'restoreVersion' | 'deleteVersion';

export interface VersionEngineOptions {
  /** The prior versions the engine holds, newest first. */
  entries?: VersionEntryDescriptor[];
  /** Calls the engine refuses, by the failure it answers with. */
  refusals?: Partial<Record<VersionCall, Error>>;
  /** Calls that never settle, which is a command still in flight. */
  hold?: readonly VersionCall[];
}

export function versionEngine({
  entries = [],
  refusals = {},
  hold = [],
}: VersionEngineOptions = {}) {
  const held = [...entries];
  const answer = <T,>(call: VersionCall, value: T): Promise<T> => {
    if (hold.includes(call)) return new Promise<never>(() => undefined);
    return refusals[call] === undefined ? Promise.resolve(value) : Promise.reject(refusals[call]);
  };

  const facade = {
    subscribe: (_listener: (event: EventDescriptor) => void) => () => undefined,
    snapshot: () => new Promise<never>(() => undefined),
    setFocus: () => Promise.resolve(),
    fileVersions: vi.fn(() => answer('fileVersions', [...held])),
    downloadVersion: vi.fn(() => answer('downloadVersion', new ArrayBuffer(4))),
    restoreVersion: vi.fn((_node: Uint8Array, contentCid: Uint8Array) => {
      // A restore swaps the head in: the named version leaves the prior list.
      if (refusals.restoreVersion === undefined) drop(held, contentCid);
      return answer('restoreVersion', DONE);
    }),
    deleteVersion: vi.fn((_node: Uint8Array, contentCid: Uint8Array) => {
      if (refusals.deleteVersion === undefined) drop(held, contentCid);
      return answer('deleteVersion', DONE);
    }),
  };

  const client = {
    facade,
    reportFocus: () => undefined,
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;

  return { client, facade };
}

/** One prior version the engine holds. */
export function versionEntry(
  fill: number,
  overrides: Partial<VersionEntryDescriptor> = {}
): VersionEntryDescriptor {
  return {
    contentCid: new Uint8Array(16).fill(fill),
    size: 1024n,
    modifiedAt: 1_700_000_000_000n,
    ...overrides,
  };
}

export function renderWithEngine(ui: ReactElement, client: EngineClient) {
  const wrap = (tree: ReactElement) => (
    <EngineProvider createClient={() => client}>{tree}</EngineProvider>
  );
  const view = render(wrap(ui));
  // Re-wrapping keeps the same provider instance, so a rerender swaps only the
  // subject under test and never rebuilds the engine.
  return { ...view, rerender: (next: ReactElement) => view.rerender(wrap(next)) };
}

function drop(held: VersionEntryDescriptor[], contentCid: Uint8Array): void {
  const at = held.findIndex((entry) =>
    entry.contentCid.every((byte: number, i: number) => byte === contentCid[i])
  );
  if (at >= 0) held.splice(at, 1);
}
