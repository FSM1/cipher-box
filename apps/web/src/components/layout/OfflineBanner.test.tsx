import { act, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { fakeEngine, view } from '../../engine/testFakes';
import { EngineProvider } from '../../providers/EngineProvider';
import { OfflineBanner } from './OfflineBanner';

function draw(client: ReturnType<typeof fakeEngine>['client']) {
  return render(
    <EngineProvider createClient={() => client}>
      <OfflineBanner />
    </EngineProvider>
  );
}

describe('the offline banner', () => {
  it('stays down while the engine is reconciling', () => {
    draw(fakeEngine().client);
    expect(screen.queryByTestId('offline-banner')).toBeNull();
  });

  it('follows the engine reaching the offline rung', async () => {
    const engine = fakeEngine();
    draw(engine.client);

    await act(async () => {
      engine.emit({ kind: 'stalenessChanged', staleness: 'offline' });
    });

    await waitFor(() => expect(screen.getByTestId('offline-banner')).toBeTruthy());
  });

  it('clears when the engine leaves that rung', async () => {
    const engine = fakeEngine();
    draw(engine.client);
    await act(async () => {
      engine.emit({ kind: 'stalenessChanged', staleness: 'offline' });
    });
    await waitFor(() => expect(screen.getByTestId('offline-banner')).toBeTruthy());

    await act(async () => {
      engine.emit({ kind: 'snapshotUpdated' });
      engine.pulls[0].resolve(view());
    });

    await waitFor(() => expect(screen.queryByTestId('offline-banner')).toBeNull());
  });

  it('renders no banner for the rungs above it', async () => {
    const engine = fakeEngine();
    draw(engine.client);

    for (const rung of ['fresh', 'reconciling', 'stale'] as const) {
      await act(async () => {
        engine.emit({ kind: 'stalenessChanged', staleness: rung });
      });
      expect(screen.queryByTestId('offline-banner')).toBeNull();
    }
  });
});
