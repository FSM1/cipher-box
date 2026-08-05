import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { fakeEngine } from '../../engine/testFakes';
import { EngineProvider } from '../../providers/EngineProvider';
import { StatusIndicator } from './StatusIndicator';

function draw(client: ReturnType<typeof fakeEngine>['client']) {
  return render(
    <EngineProvider createClient={() => client}>
      <StatusIndicator />
    </EngineProvider>
  );
}

describe('the status indicator', () => {
  it('names the rung the engine reports', async () => {
    const engine = fakeEngine();
    draw(engine.client);
    expect(screen.getByTestId('status-indicator').dataset.staleness).toBe('reconciling');

    for (const rung of ['fresh', 'stale', 'offline'] as const) {
      await act(async () => {
        engine.emit({ kind: 'stalenessChanged', staleness: rung });
      });
      await waitFor(() =>
        expect(screen.getByTestId('status-indicator').dataset.staleness).toBe(rung)
      );
    }
  });

  it('drives a manual refresh from the rung it renders', async () => {
    const engine = fakeEngine();
    draw(engine.client);
    await waitFor(() => expect(screen.getByTestId('status-indicator')).toBeTruthy());

    await act(async () => {
      fireEvent.click(screen.getByTestId('status-indicator'));
    });

    expect(engine.refreshes()).toBe(1);
    expect(engine.pulls).toHaveLength(1);
  });
});
