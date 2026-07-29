import type { EngineClient, EventDescriptor, SnapshotDescriptor } from '@cipherbox/client';
import { act, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { EngineProvider } from '../providers/EngineProvider';
import { VAULT_ROOT_NODE_ID } from './snapshotStore';
import { useSnapshot } from './useSnapshot';
import { useStaleness } from './useStaleness';

function scriptedClient() {
  const listeners = new Set<(event: EventDescriptor) => void>();
  let resolvePull: ((view: SnapshotDescriptor) => void) | null = null;

  const client = {
    facade: {
      subscribe(listener: (event: EventDescriptor) => void) {
        listeners.add(listener);
        return () => listeners.delete(listener);
      },
      snapshot: () =>
        new Promise<SnapshotDescriptor>((resolve) => {
          resolvePull = resolve;
        }),
      setFocus: () => Promise.resolve(),
    },
    reportFocus: () => undefined,
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;

  return {
    client,
    emit: (event: EventDescriptor) => {
      for (const listener of listeners) listener(event);
    },
    settle: (children: number) =>
      resolvePull?.({
        root: VAULT_ROOT_NODE_ID,
        folder: VAULT_ROOT_NODE_ID,
        children: Array.from({ length: children }, (_, i) => ({
          id: new Uint8Array(16).fill(i + 1),
          name: `child-${i}`,
          kind: 'file' as const,
          size: null,
          mtime: null,
          pending: 'none' as const,
          deadLetter: false,
          contentVersion: null,
        })),
        ancestors: [],
        deadLetters: [],
        retainedRecords: 0,
        staleness: 'fresh',
      }),
  };
}

function Probe() {
  const { view, error } = useSnapshot();
  const staleness = useStaleness();
  return (
    <>
      <span data-testid="children">{view ? String(view.children.length) : 'loading'}</span>
      <span data-testid="staleness">{staleness}</span>
      <span data-testid="error">{error ?? 'none'}</span>
    </>
  );
}

describe('useSnapshot / useStaleness', () => {
  it('repaints when the engine emits, without an independent writer', async () => {
    const engine = scriptedClient();
    render(
      <EngineProvider createClient={() => engine.client}>
        <Probe />
      </EngineProvider>
    );

    expect(screen.getByTestId('children').textContent).toBe('loading');

    await act(async () => {
      engine.emit({ kind: 'stalenessChanged', staleness: 'stale' });
      engine.emit({ kind: 'snapshotUpdated' });
      await Promise.resolve();
      engine.settle(3);
      await Promise.resolve();
    });

    expect(screen.getByTestId('children').textContent).toBe('3');
    expect(screen.getByTestId('error').textContent).toBe('none');
    expect(screen.getByTestId('staleness').textContent).toBe('fresh');
  });
});
