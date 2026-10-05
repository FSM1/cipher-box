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

  it('renders owed rotation work once per scope, however many passes report it', async () => {
    const engine = fakeEngine();
    draw(engine.client);
    const scopeRoot = new Uint8Array(16).fill(7);

    await act(async () => {
      engine.emit({
        kind: 'rotationWorkOwed',
        scopeRoot,
        detail: 'unavailable',
        retryable: true,
        class: 'availability',
      });
      engine.emit({
        kind: 'rotationWorkOwed',
        scopeRoot,
        detail: 'unavailable',
        retryable: true,
        class: 'availability',
      });
    });

    const notices = await screen.findAllByTestId('notification-notice');
    expect(notices).toHaveLength(1);
    expect(notices[0].textContent).toContain('not finished');
    expect(notices[0].textContent).not.toContain('unavailable');
  });

  it('renders owed rotation work that was dropped as a warning without its detail', async () => {
    const engine = fakeEngine();
    draw(engine.client);

    await act(async () => {
      engine.emit({
        kind: 'rotationWorkAbandoned',
        scopeRoot: new Uint8Array(16).fill(8),
        detail: 'owed-scope-not-indexed',
      });
    });

    const notice = await screen.findByTestId('notification-notice');
    expect(notice.textContent).toContain('could not be finished');
    expect(notice.textContent).not.toContain('owed-scope-not-indexed');
  });

  it('renders a write cut another device has not finished as a warning', async () => {
    const engine = fakeEngine();
    draw(engine.client);

    await act(async () => {
      engine.emit({ kind: 'writeCutUnfinished', scopeRoot: new Uint8Array(16).fill(9) });
    });

    const notice = await screen.findByTestId('notification-notice');
    expect(notice.textContent).toContain('another of your devices');
  });

  it('finishes a write cut another device has not finished from the notice', async () => {
    const engine = fakeEngine();
    draw(engine.client);
    const scopeRoot = new Uint8Array(16).fill(9);
    await act(async () => {
      engine.emit({ kind: 'writeCutUnfinished', scopeRoot });
    });

    await act(async () => {
      fireEvent.click(await screen.findByRole('button', { name: '[finish it here]' }));
    });

    expect(engine.writeCuts).toEqual([scopeRoot]);
    expect(screen.queryByTestId('notification-toast')).toBeNull();
  });

  it('keeps the notice and says so when the engine refuses the write cut', async () => {
    const engine = fakeEngine();
    engine.refuseWriteCut(new Error('rotation-work-owed'));
    draw(engine.client);
    await act(async () => {
      engine.emit({ kind: 'writeCutUnfinished', scopeRoot: new Uint8Array(16).fill(9) });
    });

    await act(async () => {
      fireEvent.click(await screen.findByRole('button', { name: '[finish it here]' }));
    });

    const notices = screen.getAllByTestId('notification-notice');
    expect(notices).toHaveLength(2);
    expect(notices[1].textContent).toContain('did not finish on this device');
    expect(notices[1].textContent).not.toContain('rotation-work-owed');
    expect(screen.getByRole('button', { name: '[finish it here]' })).toHaveProperty(
      'disabled',
      false
    );
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
