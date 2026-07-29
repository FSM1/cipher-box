import { act, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { EngineProvider } from '../providers/EngineProvider';
import { ROOT_ID, fakeEngine, view } from './testFakes';
import { useSnapshot } from './useSnapshot';
import { useStaleness } from './useStaleness';

function Probe() {
  const { view: snapshot, error } = useSnapshot();
  const staleness = useStaleness();
  return (
    <>
      <span data-testid="children">{snapshot ? String(snapshot.children.length) : 'loading'}</span>
      <span data-testid="staleness">{staleness}</span>
      <span data-testid="error">{error?.message ?? 'none'}</span>
    </>
  );
}

describe('useSnapshot / useStaleness', () => {
  it('repaints when the engine emits, without an independent writer', async () => {
    const engine = fakeEngine();
    render(
      <EngineProvider createClient={() => engine.client}>
        <Probe />
      </EngineProvider>
    );

    expect(screen.getByTestId('children').textContent).toBe('loading');
    expect(screen.getByTestId('staleness').textContent).toBe('reconciling');

    await act(async () => {
      engine.emit({ kind: 'snapshotUpdated' });
      engine.pulls[0].resolve(view(ROOT_ID, 'fresh', 3));
      await Promise.resolve();
    });

    expect(screen.getByTestId('children').textContent).toBe('3');
    expect(screen.getByTestId('error').textContent).toBe('none');
    expect(screen.getByTestId('staleness').textContent).toBe('fresh');
  });

  it('renders a staleness change with no snapshot pulled', async () => {
    const engine = fakeEngine();
    render(
      <EngineProvider createClient={() => engine.client}>
        <Probe />
      </EngineProvider>
    );

    await act(async () => {
      engine.emit({ kind: 'stalenessChanged', staleness: 'offline' });
      await Promise.resolve();
    });

    expect(screen.getByTestId('staleness').textContent).toBe('offline');
    expect(screen.getByTestId('children').textContent).toBe('loading');
  });
});
