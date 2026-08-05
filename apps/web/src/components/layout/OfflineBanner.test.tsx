import { act, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { fakeEngine, view } from '../../engine/testFakes';
import { EngineProvider } from '../../providers/EngineProvider';
import { OfflineBanner } from './OfflineBanner';

function setOnline(online: boolean): void {
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: online });
  window.dispatchEvent(new Event(online ? 'online' : 'offline'));
}

afterEach(() => setOnline(true));

function draw(client: ReturnType<typeof fakeEngine>['client']) {
  return render(
    <EngineProvider createClient={() => client}>
      <OfflineBanner />
    </EngineProvider>
  );
}

describe('the offline banner', () => {
  it('stays down while the link is up and the engine is reconciling', () => {
    draw(fakeEngine().client);
    expect(screen.queryByTestId('offline-banner')).toBeNull();
  });

  it('follows the browser losing its link', async () => {
    draw(fakeEngine().client);

    await act(async () => setOnline(false));

    expect(screen.getByTestId('offline-banner')).toBeTruthy();
  });

  it('follows the engine reaching the offline rung', async () => {
    const engine = fakeEngine();
    draw(engine.client);

    // The link is up; nothing answers over it.
    await act(async () => {
      engine.emit({ kind: 'stalenessChanged', staleness: 'offline' });
    });

    await waitFor(() => expect(screen.getByTestId('offline-banner')).toBeTruthy());
  });

  it('clears once both signals recover', async () => {
    const engine = fakeEngine();
    draw(engine.client);
    await act(async () => setOnline(false));
    await act(async () => {
      engine.emit({ kind: 'stalenessChanged', staleness: 'offline' });
    });
    expect(screen.getByTestId('offline-banner')).toBeTruthy();

    await act(async () => setOnline(true));
    expect(screen.getByTestId('offline-banner')).toBeTruthy();

    await act(async () => {
      engine.emit({ kind: 'snapshotUpdated' });
      engine.pulls[0].resolve(view());
    });

    await waitFor(() => expect(screen.queryByTestId('offline-banner')).toBeNull());
  });
});
