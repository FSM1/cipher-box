import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PendingApprovalDescriptor } from '@cipherbox/client';
import { authStore } from '../../stores/auth.store';
import {
  authWrapper,
  FAKE_APPROVE_PAYLOAD,
  FAKE_DENY_PAYLOAD,
  FAKE_DEVICE_PUBLIC_KEY,
  FAKE_EPHEMERAL_PUBLIC_KEY,
  FAKE_MINTED_FACTOR_ID,
  FAKE_REGISTERED_DEVICE,
  FAKE_SEALED_FACTOR,
  fakeComparisonValue,
  fakeCoreKitSession,
  fakeEngineClient,
  fakeSignatureOver,
  holdsNoSecret,
  type CoreKitCalls,
  type EngineCalls,
} from '../../test/authFakes';
import { ApprovalPrompt } from './ApprovalPrompt';

const REQUEST_ID = 'request-01';

/** The key of the browser asking to be let in, which is not this browser's. */
const REQUESTER = 'dd'.repeat(32);

const PENDING: PendingApprovalDescriptor = {
  requestId: REQUEST_ID,
  requesterDevicePublicKey: REQUESTER,
  ephemeralPublicKey: FAKE_EPHEMERAL_PUBLIC_KEY,
  comparisonValue: fakeComparisonValue(REQUESTER, FAKE_EPHEMERAL_PUBLIC_KEY),
  createdAt: '2026-08-31T09:00:00.000Z',
  expiresAt: new Date(Date.now() + 4 * 60_000).toISOString(),
};

interface Mounted {
  engine: EngineCalls;
  coreKit: CoreKitCalls;
}

/**
 * Mounts the prompt over an account that carries a factor policy, on a device
 * the registry carries, with one row waiting.
 */
async function prompt(pending: PendingApprovalDescriptor[] = [PENDING]): Promise<Mounted> {
  const engine = fakeEngineClient({
    pendingApprovals: () => Promise.resolve(pending),
    devices: () => Promise.resolve([FAKE_REGISTERED_DEVICE]),
  });
  const coreKit = fakeCoreKitSession({ loggedIn: true });
  authStore.factorPolicy(true);
  render(<ApprovalPrompt />, { wrapper: authWrapper(engine.client, coreKit.session) });
  await act(async () => undefined);
  return { engine: engine.calls, coreKit: coreKit.calls };
}

describe('the device approval prompt', () => {
  beforeEach(() => authStore.signedOut());

  it('shows the comparison value the engine derived for the request', async () => {
    await prompt();

    await waitFor(() =>
      expect(screen.getByTestId('approval-comparison-value').textContent).toBe(
        PENDING.comparisonValue
      )
    );
  });

  it('counts the request down, so a member can tell a slow approver from an expired row', async () => {
    await prompt();

    await waitFor(() =>
      expect(screen.getByTestId('approval-countdown').textContent).toMatch(/\d+:\d{2}/)
    );
  });

  it('raises nothing while the account carries no factor policy', async () => {
    const engine = fakeEngineClient({
      pendingApprovals: () => Promise.resolve([PENDING]),
      devices: () => Promise.resolve([FAKE_REGISTERED_DEVICE]),
    });
    render(<ApprovalPrompt />, {
      wrapper: authWrapper(engine.client, fakeCoreKitSession({ loggedIn: true }).session),
    });
    await act(async () => undefined);

    expect(screen.queryByTestId('approval-prompt')).toBeNull();
    expect(engine.calls.rendezvous).toEqual([]);
  });

  /**
   * The pending list is account-scoped, so a device the registry does not carry
   * would raise a prompt whose answer the API refuses.
   */
  it('raises nothing on a device the account registry does not carry', async () => {
    let asked = 0;
    const engine = fakeEngineClient({
      pendingApprovals: () => {
        asked += 1;
        return Promise.resolve([PENDING]);
      },
      devices: () => Promise.resolve([{ ...FAKE_REGISTERED_DEVICE, publicKey: REQUESTER }]),
    });
    authStore.factorPolicy(true);
    render(<ApprovalPrompt />, {
      wrapper: authWrapper(engine.client, fakeCoreKitSession({ loggedIn: true }).session),
    });
    await act(async () => undefined);

    expect(screen.queryByTestId('approval-prompt')).toBeNull();
    expect(asked).toBe(0);
  });

  /** Revoking a device elsewhere leaves this session signed in and polling. */
  it('takes the prompt down once the registry stops carrying this device', async () => {
    let registry = [FAKE_REGISTERED_DEVICE];
    const engine = fakeEngineClient({
      pendingApprovals: () => Promise.resolve([PENDING]),
      devices: () => Promise.resolve(registry),
    });
    authStore.factorPolicy(true);
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<ApprovalPrompt />, {
        wrapper: authWrapper(engine.client, fakeCoreKitSession({ loggedIn: true }).session),
      });
      await waitFor(() => expect(screen.getByTestId('approval-prompt')).toBeTruthy());

      registry = [];
      // One poll interval, as the component sets it.
      await act(() => vi.advanceTimersByTimeAsync(5000));

      await waitFor(() => expect(screen.queryByTestId('approval-prompt')).toBeNull());
    } finally {
      vi.useRealTimers();
    }
  });

  it('holds the approve control shut until the member confirms the value matches', async () => {
    const { engine } = await prompt();
    await waitFor(() => expect(screen.getByTestId('approval-prompt')).toBeTruthy());

    const approve = screen.getByTestId('approval-approve') as HTMLButtonElement;
    expect(approve.disabled).toBe(true);
    await act(async () => {
      fireEvent.click(approve);
    });

    // Nothing was sealed and nothing was answered, so an unmatched value cannot
    // let a relayed request in.
    expect(engine.rendezvous).toEqual([]);
    expect(engine.answered).toEqual([]);
  });

  it('opens the approve control once the member confirms it', async () => {
    await prompt();
    await waitFor(() => expect(screen.getByTestId('approval-prompt')).toBeTruthy());

    await act(async () => {
      fireEvent.click(screen.getByTestId('approval-match'));
    });

    expect((screen.getByTestId('approval-approve') as HTMLButtonElement).disabled).toBe(false);
  });

  it('denies without asking the member to confirm anything, and seals no factor', async () => {
    const { engine, coreKit } = await prompt();
    await waitFor(() => expect(screen.getByTestId('approval-prompt')).toBeTruthy());

    await act(async () => {
      fireEvent.click(screen.getByTestId('approval-deny'));
    });

    expect(engine.rendezvous.map((step) => step.kind)).toEqual(['deny']);
    expect(engine.answered).toEqual([
      {
        requestId: REQUEST_ID,
        decision: 'deny',
        devicePublicKey: FAKE_DEVICE_PUBLIC_KEY,
        ephemeralPublicKey: FAKE_EPHEMERAL_PUBLIC_KEY,
        signature: fakeSignatureOver(FAKE_DENY_PAYLOAD),
        sealedFactor: null,
      },
    ]);
    expect(coreKit.mintedFactors).toEqual([]);
  });

  /**
   * Ordering read off the data each step carried: the seal holds the factor that
   * was just minted, the signature is over the payload the seal returned, and
   * the answer carries that signature.
   */
  it('approves by minting a factor, sealing it, then signing what the seal returned', async () => {
    const { engine, coreKit } = await prompt();
    await waitFor(() => expect(screen.getByTestId('approval-prompt')).toBeTruthy());

    await act(async () => {
      fireEvent.click(screen.getByTestId('approval-match'));
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId('approval-approve'));
    });

    expect(coreKit.mintedFactors).toHaveLength(1);
    const sealed = engine.rendezvous[0];
    expect(sealed.kind).toBe('approve');
    if (sealed.kind !== 'approve') throw new Error('the seal step was not dispatched');
    expect(sealed.factorKey).toBe(coreKit.mintedFactors[0]);
    expect(sealed.requesterDevicePublicKey).toBe(REQUESTER);
    expect(coreKit.signed).toEqual([FAKE_APPROVE_PAYLOAD]);
    expect(engine.answered).toEqual([
      {
        requestId: REQUEST_ID,
        decision: 'approve',
        devicePublicKey: FAKE_DEVICE_PUBLIC_KEY,
        ephemeralPublicKey: FAKE_EPHEMERAL_PUBLIC_KEY,
        signature: fakeSignatureOver(FAKE_APPROVE_PAYLOAD),
        sealedFactor: FAKE_SEALED_FACTOR,
      },
    ]);
  });

  /**
   * The transport transfers the seal buffers, so the views left behind are
   * detached and erasing one throws. An approve that erased blindly would fail
   * in the browser between the seal and the answer, and never respond at all.
   */
  it('answers the rendezvous even though the seal buffers were transferred away', async () => {
    const { engine } = await prompt();
    await waitFor(() => expect(screen.getByTestId('approval-prompt')).toBeTruthy());

    await act(async () => {
      fireEvent.click(screen.getByTestId('approval-match'));
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId('approval-approve'));
    });

    await waitFor(() => expect(engine.answered).toHaveLength(1));
    expect(engine.answered[0].decision).toBe('approve');
    expect(engine.answered[0].sealedFactor).toBeTruthy();
  });

  it('leaves no factor and no seal scalar in this realm once the seal is taken', async () => {
    const { engine, coreKit } = await prompt();
    await waitFor(() => expect(screen.getByTestId('approval-prompt')).toBeTruthy());

    await act(async () => {
      fireEvent.click(screen.getByTestId('approval-match'));
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId('approval-approve'));
    });

    const sealed = engine.rendezvous[0];
    if (sealed.kind !== 'approve') throw new Error('the seal step was not dispatched');
    // Both buffers move rather than clone, so this realm is left holding
    // nothing at all. A detached view has no bytes; a cloned one would still
    // read 32, which is what a regression here looks like.
    expect(sealed.factorKey.byteLength).toBe(0);
    expect(sealed.sealScalar.byteLength).toBe(0);
    expect(holdsNoSecret(coreKit.mintedFactors[0])).toBe(true);

    // The transfer moved the real factor, not an empty buffer.
    const sent = engine.rendezvousSent[0];
    if (sent.kind !== 'approve') throw new Error('the seal step was not dispatched');
    expect(sent.factorKey.some((byte) => byte !== 0)).toBe(true);
    expect(sent.sealScalar.some((byte) => byte !== 0)).toBe(true);
  });

  /**
   * The poll is a foreground beacon the server does not need, so a tab that
   * finds nothing has to stop sending it every few seconds. Counted off the
   * calls the component made, never off the timer it set.
   */
  describe('the poll back-off', () => {
    /** Mounts over a pending list this test drives, counting every poll. */
    async function mounted(rows: () => PendingApprovalDescriptor[]): Promise<() => number> {
      let asked = 0;
      const engine = fakeEngineClient({
        pendingApprovals: () => {
          asked += 1;
          return Promise.resolve(rows());
        },
        devices: () => Promise.resolve([FAKE_REGISTERED_DEVICE]),
      });
      authStore.factorPolicy(true);
      render(<ApprovalPrompt />, {
        wrapper: authWrapper(engine.client, fakeCoreKitSession({ loggedIn: true }).session),
      });
      // The mount polls at once and only then sets its first timer, so nothing
      // may advance the clock before that first run has landed.
      await waitFor(() => expect(asked).toBe(1));
      return () => asked;
    }

    /** Mounts over a pending list that never holds a row. */
    const idle = (): Promise<() => number> => mounted(() => []);

    beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }));
    afterEach(() => vi.useRealTimers());

    it('doubles the wait away from the floor while every run comes back empty', async () => {
      const asked = await idle();

      // The floor, then twice it: a fixed interval would have asked four times
      // over the same span.
      await act(() => vi.advanceTimersByTimeAsync(5000));
      await waitFor(() => expect(asked()).toBe(2));
      await act(() => vi.advanceTimersByTimeAsync(5000));
      expect(asked()).toBe(2);
      await act(() => vi.advanceTimersByTimeAsync(5000));
      await waitFor(() => expect(asked()).toBe(3));
    });

    it('stops doubling at the ceiling, so an idle tab keeps a minute cadence', async () => {
      const asked = await idle();
      // Past 5 + 10 + 20 + 40 the wait is capped, so every further minute is
      // exactly one more ask.
      await act(() => vi.advanceTimersByTimeAsync(75_000));
      await waitFor(() => expect(asked()).toBe(5));

      await act(() => vi.advanceTimersByTimeAsync(60_000));
      await waitFor(() => expect(asked()).toBe(6));
      await act(() => vi.advanceTimersByTimeAsync(60_000));
      await waitFor(() => expect(asked()).toBe(7));
    });

    it('returns to the floor as soon as a run raises a row', async () => {
      let rows: PendingApprovalDescriptor[] = [];
      const asked = await mounted(() => rows);
      // Backed off to the ceiling: 5 + 10 + 20 + 40 of doubling, then a minute.
      await act(() => vi.advanceTimersByTimeAsync(75_000));
      await waitFor(() => expect(asked()).toBe(5));

      rows = [PENDING];
      await act(() => vi.advanceTimersByTimeAsync(60_000));
      await waitFor(() => expect(asked()).toBe(6));

      // One floor-length wait now answers, which the backed-off tab spent silent.
      await act(() => vi.advanceTimersByTimeAsync(5000));
      expect(asked()).toBe(7);
    });

    it('returns to the floor when the tab regains focus', async () => {
      const visibility = vi.spyOn(document, 'visibilityState', 'get');
      try {
        const asked = await idle();
        await act(() => vi.advanceTimersByTimeAsync(75_000));
        await waitFor(() => expect(asked()).toBe(5));

        visibility.mockReturnValue('hidden');
        await act(async () => {
          document.dispatchEvent(new Event('visibilitychange'));
        });
        visibility.mockReturnValue('visible');
        await act(async () => {
          document.dispatchEvent(new Event('visibilitychange'));
        });
        // The tab polls the moment it is back on screen, then again at the floor.
        await waitFor(() => expect(asked()).toBe(6));

        await act(() => vi.advanceTimersByTimeAsync(5000));
        expect(asked()).toBe(7);
      } finally {
        visibility.mockRestore();
      }
    });
  });

  /**
   * The mint commits the factor to the account before the seal runs, so a
   * failure in between leaves one that opens nothing, and each retry leaves one
   * more. The seal transfers the bytes away, so the public identifier is the
   * only handle the tab keeps.
   */
  describe('the factor an approval minted', () => {
    /** Mounts over the given rows with a seal and a send this test drives. */
    async function answering(
      rows: PendingApprovalDescriptor[],
      overrides: {
        deviceRendezvous?: () => Promise<never> | undefined;
        respondToApproval?: () => Promise<never>;
      } = {}
    ): Promise<Mounted> {
      const engine = fakeEngineClient({
        ...overrides,
        pendingApprovals: () => Promise.resolve(rows),
        devices: () => Promise.resolve([FAKE_REGISTERED_DEVICE]),
      });
      const coreKit = fakeCoreKitSession({ loggedIn: true });
      authStore.factorPolicy(true);
      render(<ApprovalPrompt />, { wrapper: authWrapper(engine.client, coreKit.session) });
      await waitFor(() => expect(screen.getByTestId('approval-prompt')).toBeTruthy());
      return { engine: engine.calls, coreKit: coreKit.calls };
    }

    /** Confirms the value and approves the row on screen. */
    async function approve(): Promise<void> {
      await act(async () => {
        fireEvent.click(screen.getByTestId('approval-match'));
      });
      await act(async () => {
        fireEvent.click(screen.getByTestId('approval-approve'));
      });
    }

    it('deletes it when the approval failed before the response went out', async () => {
      const { coreKit } = await answering([PENDING], {
        deviceRendezvous: () => Promise.reject(new Error('the engine refused this seal')),
      });

      await approve();

      await waitFor(() => expect(coreKit.deletedFactors).toEqual([FAKE_MINTED_FACTOR_ID]));
      expect(coreKit.mintedFactors).toHaveLength(1);
    });

    /**
     * A refusal and a lost acknowledgement look alike from here, and deleting
     * the factor of a response the API did accept strands the device it let in.
     */
    it('keeps it when the response was already sent', async () => {
      const { engine, coreKit } = await answering([PENDING], {
        respondToApproval: () => Promise.reject(new Error('the answer did not land')),
      });

      await approve();

      await waitFor(() => expect(engine.answered).toHaveLength(1));
      expect(coreKit.deletedFactors).toEqual([]);
    });

    it('holds no record of it once the exchange has succeeded', async () => {
      const second: PendingApprovalDescriptor = { ...PENDING, requestId: 'request-02' };
      let seals = 0;
      const { coreKit } = await answering([PENDING, second], {
        deviceRendezvous: () => {
          seals += 1;
          return seals === 1
            ? undefined
            : Promise.reject(new Error('the engine refused this seal'));
        },
      });

      await approve();
      // The next row fails at its own seal, and it is a denial, so it minted
      // nothing. A record left over from the first answer would be deleted here.
      await waitFor(() => expect(screen.getByTestId('approval-prompt')).toBeTruthy());
      await act(async () => {
        fireEvent.click(screen.getByTestId('approval-deny'));
      });

      await waitFor(() => expect(seals).toBe(2));
      expect(coreKit.deletedFactors).toEqual([]);
    });

    it('mints nothing and deletes nothing for a denial', async () => {
      const { coreKit } = await answering([PENDING], {
        deviceRendezvous: () => Promise.reject(new Error('the engine refused this seal')),
      });

      await act(async () => {
        fireEvent.click(screen.getByTestId('approval-deny'));
      });

      expect(coreKit.mintedFactors).toEqual([]);
      expect(coreKit.deletedFactors).toEqual([]);
    });

    /** The member has to read what actually failed, not what the cleanup did. */
    it('reports the failure that caused the delete, not the delete', async () => {
      const engine = fakeEngineClient({
        deviceRendezvous: () => Promise.reject(new Error('the engine refused this seal')),
        pendingApprovals: () => Promise.resolve([PENDING]),
        devices: () => Promise.resolve([FAKE_REGISTERED_DEVICE]),
      });
      const coreKit = fakeCoreKitSession({ loggedIn: true });
      coreKit.session.deleteApprovalFactor = () =>
        Promise.reject(new Error('the account could not be re-synced'));
      authStore.factorPolicy(true);
      render(<ApprovalPrompt />, { wrapper: authWrapper(engine.client, coreKit.session) });
      await waitFor(() => expect(screen.getByTestId('approval-prompt')).toBeTruthy());

      await approve();

      await waitFor(() =>
        expect(screen.getByRole('alert').textContent).toContain('the engine refused this seal')
      );
    });
  });

  it('retires an answered request rather than raising it again on the next poll', async () => {
    await prompt();
    await waitFor(() => expect(screen.getByTestId('approval-prompt')).toBeTruthy());

    await act(async () => {
      fireEvent.click(screen.getByTestId('approval-deny'));
    });

    await waitFor(() => expect(screen.queryByTestId('approval-prompt')).toBeNull());
  });
});
