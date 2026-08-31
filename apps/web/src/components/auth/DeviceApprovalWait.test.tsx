import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PendingApprovalDescriptor } from '@cipherbox/client';
import { authStore } from '../../stores/auth.store';
import {
  authWrapper,
  FAKE_DEVICE_PUBLIC_KEY,
  FAKE_EPHEMERAL_PUBLIC_KEY,
  FAKE_REQUEST_PAYLOAD,
  FAKE_SEALED_FACTOR,
  fakeComparisonValue,
  fakeCoreKitSession,
  fakeEngineClient,
  holdsNoSecret,
  type CoreKitCalls,
  type EngineCalls,
} from '../../test/authFakes';
import { ApprovalPrompt } from '../devices/ApprovalPrompt';
import { DeviceApprovalWait } from './DeviceApprovalWait';

const REQUEST_ID = 'request-01';
const EXPIRES_AT = new Date(Date.now() + 4 * 60_000).toISOString();

/** One relay answer, in the shape the rendezvous routes serve. */
type RelayState = Record<string, unknown>;

const PENDING: RelayState = { status: 'pending', expiresAt: EXPIRES_AT };
const APPROVED: RelayState = {
  status: 'approved',
  expiresAt: EXPIRES_AT,
  sealedFactor: FAKE_SEALED_FACTOR,
};

interface Relay {
  /** Each request the screen made, as method and path. */
  calls: { method: string; path: string }[];
}

/**
 * The bulletin-board API the requester speaks to before it has a session. It
 * relays and inspects nothing, so a fake of it needs no state beyond the answer
 * it is told to serve.
 */
function installRelay(states: RelayState[]): Relay {
  const relay: Relay = { calls: [] };
  const queued = [...states];
  const json = (body: unknown) =>
    Promise.resolve(
      new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } })
    );
  vi.stubGlobal('fetch', (input: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET';
    const { pathname } = new URL(input);
    relay.calls.push({ method, path: pathname });
    if (pathname === '/device-approval/session') return json({ accessToken: 'scoped-token' });
    if (method === 'POST') return json({ requestId: REQUEST_ID, expiresAt: EXPIRES_AT });
    if (method === 'GET') return json(queued.length > 1 ? queued.shift() : queued[0]);
    return Promise.resolve(new Response(null, { status: 204 }));
  });
  return relay;
}

interface Mounted {
  relay: Relay;
  engine: EngineCalls;
  coreKit: CoreKitCalls;
  usedPhrase: () => number;
  cancelled: () => number;
}

/** Mounts the wait screen over a login held at the factor policy. */
async function waiting(states: RelayState[] = [PENDING]): Promise<Mounted> {
  const relay = installRelay(states);
  const engine = fakeEngineClient();
  const coreKit = fakeCoreKitSession({ needsRecovery: true });
  authStore.recoveryRequired();
  let usedPhrase = 0;
  let cancelled = 0;
  render(
    <DeviceApprovalWait
      onUseRecoveryPhrase={() => (usedPhrase += 1)}
      onCancel={() => (cancelled += 1)}
    />,
    { wrapper: authWrapper(engine.client, coreKit.session) }
  );
  await act(async () => undefined);
  return {
    relay,
    engine: engine.calls,
    coreKit: coreKit.calls,
    usedPhrase: () => usedPhrase,
    cancelled: () => cancelled,
  };
}

const value = () => screen.getByTestId('approval-comparison-value').textContent;

describe('the device approval wait', () => {
  beforeEach(() => authStore.signedOut());
  afterEach(() => vi.unstubAllGlobals());

  it('opens the rendezvous over a signature the device identity key took', async () => {
    const { engine, coreKit } = await waiting();

    await waitFor(() => expect(engine.rendezvous).toHaveLength(1));
    const opened = engine.rendezvous[0];
    expect(opened.kind).toBe('open');
    if (opened.kind !== 'open') throw new Error('the open step was not dispatched');
    expect(opened.devicePublicKey).toBe(FAKE_DEVICE_PUBLIC_KEY);
    expect(coreKit.signed).toEqual([FAKE_REQUEST_PAYLOAD]);
  });

  it('shows the comparison value the engine derived for this rendezvous', async () => {
    await waiting();

    await waitFor(() =>
      expect(value()).toBe(fakeComparisonValue(FAKE_DEVICE_PUBLIC_KEY, FAKE_EPHEMERAL_PUBLIC_KEY))
    );
  });

  /**
   * The whole defence: the approver is handed the transcript this screen put on
   * the relay, and both sides read the same digits out of it.
   */
  it('reads out the value the approver is shown for the transcript it opened', async () => {
    const { engine } = await waiting();
    await waitFor(() => expect(value()).toBeTruthy());

    const opened = engine.rendezvous.find((step) => step.kind === 'open');
    if (opened?.kind !== 'open') throw new Error('the open step was not dispatched');
    const relayed: PendingApprovalDescriptor = {
      requestId: REQUEST_ID,
      requesterDevicePublicKey: opened.devicePublicKey,
      ephemeralPublicKey: FAKE_EPHEMERAL_PUBLIC_KEY,
      comparisonValue: fakeComparisonValue(opened.devicePublicKey, FAKE_EPHEMERAL_PUBLIC_KEY),
      createdAt: '2026-08-31T09:00:00.000Z',
      expiresAt: EXPIRES_AT,
    };
    const approver = fakeEngineClient({ pendingApprovals: () => Promise.resolve([relayed]) });
    authStore.recoveryEnrollment(true);
    render(<ApprovalPrompt />, {
      wrapper: authWrapper(approver.client, fakeCoreKitSession({ loggedIn: true }).session),
    });

    await waitFor(() => expect(screen.getAllByTestId('approval-comparison-value')).toHaveLength(2));
    const [requesterSees, approverSees] = screen
      .getAllByTestId('approval-comparison-value')
      .map((shown) => shown.textContent);
    expect(approverSees).toBe(requesterSees);
  });

  /**
   * The other half of the defence: a relay that moves either field it relays
   * moves the approver's digits, and the member sees two screens disagree.
   */
  it('reads out a different value when the relay moves the key it relayed', async () => {
    const { engine } = await waiting();
    await waitFor(() => expect(value()).toBeTruthy());

    const opened = engine.rendezvous.find((step) => step.kind === 'open');
    if (opened?.kind !== 'open') throw new Error('the open step was not dispatched');
    const substituted = `03${'cc'.repeat(32)}`;
    const relayed: PendingApprovalDescriptor = {
      requestId: REQUEST_ID,
      requesterDevicePublicKey: opened.devicePublicKey,
      ephemeralPublicKey: substituted,
      comparisonValue: fakeComparisonValue(opened.devicePublicKey, substituted),
      createdAt: '2026-08-31T09:00:00.000Z',
      expiresAt: EXPIRES_AT,
    };
    const approver = fakeEngineClient({ pendingApprovals: () => Promise.resolve([relayed]) });
    authStore.recoveryEnrollment(true);
    render(<ApprovalPrompt />, {
      wrapper: authWrapper(approver.client, fakeCoreKitSession({ loggedIn: true }).session),
    });

    await waitFor(() => expect(screen.getAllByTestId('approval-comparison-value')).toHaveLength(2));
    const [requesterSees, approverSees] = screen
      .getAllByTestId('approval-comparison-value')
      .map((shown) => shown.textContent);
    expect(approverSees).not.toBe(requesterSees);
  });

  it('keeps the recovery phrase one click away, because it needs no second device', async () => {
    const { usedPhrase } = await waiting();

    await act(async () => {
      fireEvent.click(screen.getByTestId('device-approval-use-phrase'));
    });

    expect(usedPhrase()).toBe(1);
  });

  it('abandons the rendezvous and zeroes the scalar when the member takes the phrase instead', async () => {
    const { relay, engine } = await waiting();
    await waitFor(() => expect(value()).toBeTruthy());

    await act(async () => {
      fireEvent.click(screen.getByTestId('device-approval-use-phrase'));
    });

    const opened = engine.rendezvous[0];
    if (opened.kind !== 'open') throw new Error('the open step was not dispatched');
    expect(holdsNoSecret(opened.scalar)).toBe(true);
    // A row left open is one an approver is still asked to answer.
    await waitFor(() =>
      expect(relay.calls).toContainEqual({
        method: 'DELETE',
        path: `/device-approval/requests/${REQUEST_ID}`,
      })
    );
  });

  it('abandons the rendezvous and zeroes the scalar when the member cancels', async () => {
    const { relay, engine, cancelled } = await waiting();
    await waitFor(() => expect(value()).toBeTruthy());

    await act(async () => {
      fireEvent.click(screen.getByTestId('device-approval-cancel'));
    });

    const opened = engine.rendezvous[0];
    if (opened.kind !== 'open') throw new Error('the open step was not dispatched');
    expect(holdsNoSecret(opened.scalar)).toBe(true);
    await waitFor(() =>
      expect(relay.calls).toContainEqual({
        method: 'DELETE',
        path: `/device-approval/requests/${REQUEST_ID}`,
      })
    );
    expect(cancelled()).toBe(1);
  });

  it('opens the sealed factor with its own scalar and adopts it', async () => {
    const { engine, coreKit } = await waiting([APPROVED]);

    await waitFor(() => expect(coreKit.adoptedBytes).toHaveLength(1));
    const factor = engine.rendezvous.find((step) => step.kind === 'openFactor');
    expect(factor?.kind).toBe('openFactor');
    if (factor?.kind !== 'openFactor') throw new Error('the factor step was not dispatched');
    expect(factor.sealedFactor).toBe(FAKE_SEALED_FACTOR);
    expect(factor.requesterDevicePublicKey).toBe(FAKE_DEVICE_PUBLIC_KEY);
    // The engine was handed something to open, not a blank scalar.
    expect(holdsNoSecret(coreKit.adoptedBytes[0])).toBe(false);
  });

  it('leaves neither the scalar nor the adopted factor in this realm once the login is finished', async () => {
    const { engine, coreKit } = await waiting([APPROVED]);

    await waitFor(() => expect(coreKit.adopted).toHaveLength(1));
    const opened = engine.rendezvous[0];
    if (opened.kind !== 'open') throw new Error('the open step was not dispatched');
    await waitFor(() => expect(holdsNoSecret(opened.scalar)).toBe(true));
    await waitFor(() => expect(holdsNoSecret(coreKit.adopted[0])).toBe(true));
  });

  it('ends the wait with its own message when the other device turned it down', async () => {
    await waiting([{ status: 'denied', expiresAt: EXPIRES_AT }]);

    await waitFor(() =>
      expect(screen.getByTestId('device-approval-stage').textContent).toContain('turned this')
    );
  });

  it('ends it when the request expired before anyone answered', async () => {
    const relay = installRelay([]);
    vi.stubGlobal('fetch', (input: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET';
      const { pathname } = new URL(input);
      relay.calls.push({ method, path: pathname });
      if (pathname === '/device-approval/session') {
        return Promise.resolve(new Response(JSON.stringify({ accessToken: 'scoped-token' })));
      }
      if (method === 'POST') {
        return Promise.resolve(
          new Response(JSON.stringify({ requestId: REQUEST_ID, expiresAt: EXPIRES_AT }))
        );
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    const engine = fakeEngineClient();
    render(
      <DeviceApprovalWait onUseRecoveryPhrase={() => undefined} onCancel={() => undefined} />,
      {
        wrapper: authWrapper(engine.client, fakeCoreKitSession({ needsRecovery: true }).session),
      }
    );

    await waitFor(() =>
      expect(screen.getByTestId('device-approval-stage').textContent).toContain('expired')
    );
  });
});
