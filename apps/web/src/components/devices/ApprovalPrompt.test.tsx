import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import type { PendingApprovalDescriptor } from '@cipherbox/client';
import { authStore } from '../../stores/auth.store';
import {
  authWrapper,
  FAKE_APPROVE_PAYLOAD,
  FAKE_DENY_PAYLOAD,
  FAKE_DEVICE_PUBLIC_KEY,
  FAKE_EPHEMERAL_PUBLIC_KEY,
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

/** Mounts the prompt over an account that carries a factor policy and one row. */
async function prompt(pending: PendingApprovalDescriptor[] = [PENDING]): Promise<Mounted> {
  const engine = fakeEngineClient({ pendingApprovals: () => Promise.resolve(pending) });
  const coreKit = fakeCoreKitSession({ loggedIn: true });
  authStore.recoveryEnrollment(true);
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
    const engine = fakeEngineClient({ pendingApprovals: () => Promise.resolve([PENDING]) });
    render(<ApprovalPrompt />, {
      wrapper: authWrapper(engine.client, fakeCoreKitSession({ loggedIn: true }).session),
    });
    await act(async () => undefined);

    expect(screen.queryByTestId('approval-prompt')).toBeNull();
    expect(engine.calls.rendezvous).toEqual([]);
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

  it('retires an answered request rather than raising it again on the next poll', async () => {
    await prompt();
    await waitFor(() => expect(screen.getByTestId('approval-prompt')).toBeTruthy());

    await act(async () => {
      fireEvent.click(screen.getByTestId('approval-deny'));
    });

    await waitFor(() => expect(screen.queryByTestId('approval-prompt')).toBeNull());
  });
});
