import { act, render, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { EngineProvider } from '../providers/EngineProvider';
import { fakeEngine, setOnline, setVisible } from './testFakes';
import { useRefreshHints } from './useRefreshHints';

afterEach(() => {
  setOnline(true);
  setVisible(true);
});

function Hints() {
  useRefreshHints();
  return null;
}

function draw(client: ReturnType<typeof fakeEngine>['client']) {
  return render(
    <EngineProvider createClient={() => client}>
      <Hints />
    </EngineProvider>
  );
}

describe('refresh hints', () => {
  it('does not refresh on mount', async () => {
    const engine = fakeEngine();
    draw(engine.client);
    await waitFor(() => expect(engine.subscriberCount()).toBe(1));

    expect(engine.refreshes()).toBe(0);
  });

  it('refreshes when the network comes back', async () => {
    const engine = fakeEngine();
    draw(engine.client);
    await waitFor(() => expect(engine.subscriberCount()).toBe(1));

    await act(async () => setOnline(false));
    expect(engine.refreshes()).toBe(0);

    await act(async () => setOnline(true));
    expect(engine.refreshes()).toBe(1);
  });

  it('refreshes when a backgrounded tab comes back on screen', async () => {
    const engine = fakeEngine();
    draw(engine.client);
    await waitFor(() => expect(engine.subscriberCount()).toBe(1));

    await act(async () => setVisible(false));
    await act(async () => setVisible(true));

    expect(engine.refreshes()).toBe(1);
  });

  it('waits for both signals before refreshing', async () => {
    const engine = fakeEngine();
    draw(engine.client);
    await waitFor(() => expect(engine.subscriberCount()).toBe(1));

    await act(async () => setVisible(false));
    await act(async () => setOnline(false));
    await act(async () => setOnline(true));
    // Still hidden: nothing on screen is waiting on a fresher answer.
    expect(engine.refreshes()).toBe(0);

    await act(async () => setVisible(true));
    expect(engine.refreshes()).toBe(1);
  });
});
