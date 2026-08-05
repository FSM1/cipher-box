import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { NotificationToast } from '../components/NotificationToast';
import { StatusIndicator } from '../components/layout/StatusIndicator';
import { EngineProvider } from '../providers/EngineProvider';
import { notificationStore } from '../stores/notification.store';
import { fakeEngine } from './testFakes';

afterEach(() => notificationStore.clear());

/** The two surfaces side by side, so one event cannot land on both. */
function draw(client: ReturnType<typeof fakeEngine>['client']) {
  return render(
    <EngineProvider createClient={() => client}>
      <StatusIndicator />
      <NotificationToast />
    </EngineProvider>
  );
}

describe('engine warnings', () => {
  it('renders a withheld-update escalation as a warning, never as staleness', async () => {
    const engine = fakeEngine();
    draw(engine.client);
    await waitFor(() => expect(screen.getByTestId('status-indicator')).toBeTruthy());
    const rung = screen.getByTestId('status-indicator').dataset.staleness;

    await act(async () => {
      engine.emit({ kind: 'withheldUpdateEscalation', ipnsName: new Uint8Array([0xab, 0xcd]) });
    });

    const notice = await screen.findByTestId('notification-notice');
    expect(notice.getAttribute('role')).toBe('alert');
    // The pinned name identifies the scope for de-duplication only.
    expect(notice.textContent).not.toContain('abcd');
    // The ladder is untouched: a trust warning is never a rung.
    expect(screen.getByTestId('status-indicator').dataset.staleness).toBe(rung);
  });

  it('renders an attributable-abuse report as the same warning class', async () => {
    const engine = fakeEngine();
    draw(engine.client);

    await act(async () => {
      engine.emit({ kind: 'attributableAbuse', description: 'k51abc: floor regression' });
    });

    const notice = await screen.findByTestId('notification-notice');
    expect(notice.textContent).toContain('k51abc: floor regression');
    expect(screen.getByTestId('status-indicator').dataset.staleness).toBe('reconciling');
  });

  it('collapses a scope that escalates on every tick', async () => {
    const engine = fakeEngine();
    draw(engine.client);
    const name = new Uint8Array([0x01, 0x02]);

    await act(async () => {
      engine.emit({ kind: 'withheldUpdateEscalation', ipnsName: name });
      engine.emit({ kind: 'withheldUpdateEscalation', ipnsName: name });
      engine.emit({ kind: 'withheldUpdateEscalation', ipnsName: name });
    });

    expect(await screen.findAllByTestId('notification-notice')).toHaveLength(1);
  });

  it('dismisses a warning the reader has read', async () => {
    const engine = fakeEngine();
    draw(engine.client);
    await act(async () => {
      engine.emit({ kind: 'attributableAbuse', description: 'refused' });
    });
    await screen.findByTestId('notification-notice');

    fireEvent.click(screen.getByLabelText('Dismiss warning'));

    expect(screen.queryByTestId('notification-toast')).toBeNull();
  });

  it('drops the warnings with the engine that raised them', async () => {
    const engine = fakeEngine();
    const { unmount } = draw(engine.client);
    await act(async () => {
      engine.emit({ kind: 'attributableAbuse', description: 'refused' });
    });
    await screen.findByTestId('notification-notice');

    unmount();

    expect(notificationStore.getState()).toHaveLength(0);
  });

  it('leaves the staleness ladder to the events that own it', async () => {
    const engine = fakeEngine();
    draw(engine.client);

    await act(async () => {
      engine.emit({ kind: 'stalenessChanged', staleness: 'stale' });
    });

    await waitFor(() =>
      expect(screen.getByTestId('status-indicator').dataset.staleness).toBe('stale')
    );
    expect(screen.queryByTestId('notification-toast')).toBeNull();
  });
});
