import { act, render, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { fakeEngine } from '../engine/testFakes';
import type { SnapshotStore } from '../engine/snapshotStore';
import { EngineProvider, useSnapshotStore } from '../providers/EngineProvider';
import { useFolderPicker } from './useFolderPicker';

const HOME = new Uint8Array(16).fill(1);
const NEXT = new Uint8Array(16).fill(2);

function Picker() {
  useFolderPicker(HOME, new Set());
  return null;
}

/** Publishes the provider's store so the test can drive the route's writer. */
function Probe({ onStore }: { onStore: (store: SnapshotStore) => void }) {
  onStore(useSnapshotStore());
  return null;
}

describe('the folder picker', () => {
  it('leaves the engine on the folder the store is focused on', async () => {
    const engine = fakeEngine();
    let store!: SnapshotStore;
    const { rerender } = render(
      <EngineProvider createClient={() => engine.client}>
        <Probe onStore={(next) => (store = next)} />
        <Picker />
      </EngineProvider>
    );
    await waitFor(() => expect(engine.focus.length).toBeGreaterThan(0));

    // The route moves under the open dialog, then the dialog closes.
    await act(async () => {
      store.setFocus(NEXT);
    });
    // The store's own write already names NEXT, so only a *further* write proves
    // the close re-asserted the window rather than inheriting it.
    const written = engine.focus.length;
    const reported = engine.reported.length;
    rerender(
      <EngineProvider createClient={() => engine.client}>
        <Probe onStore={(next) => (store = next)} />
      </EngineProvider>
    );

    await waitFor(() => expect(engine.focus.length).toBeGreaterThan(written));
    expect(engine.reported.length).toBeGreaterThan(reported);
    expect(engine.focus.at(-1)).toBe(NEXT);
    expect(engine.reported.at(-1)).toBe(NEXT);
  });
});
