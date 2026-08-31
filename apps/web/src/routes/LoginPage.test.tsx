import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { authStore } from '../stores/auth.store';
import { fakeCoreKitSession, fakeEngineClient, pageWrapper } from '../test/authFakes';
import { LoginPage } from './LoginPage';

/** The relay the wait screen mints its scoped session from. */
function installRelay(): void {
  vi.stubGlobal('fetch', (input: string, init?: RequestInit) => {
    const { pathname } = new URL(input);
    const body =
      pathname === '/device-approval/session'
        ? { accessToken: 'scoped-token' }
        : { requestId: 'request-01', expiresAt: new Date(Date.now() + 60_000).toISOString() };
    return Promise.resolve(
      new Response(JSON.stringify((init?.method ?? 'GET') === 'GET' ? { status: 'pending' } : body))
    );
  });
}

/** The front door over a login held at the factor policy. */
async function heldAtPolicy(): Promise<void> {
  const engine = fakeEngineClient();
  const session = fakeCoreKitSession({ needsRecovery: true }).session;
  authStore.recoveryRequired();
  const Providers = pageWrapper(engine.client, session);
  render(
    <Providers>
      <MemoryRouter initialEntries={['/']}>
        <LoginPage />
      </MemoryRouter>
    </Providers>
  );
  await act(async () => undefined);
}

describe('the front door held at the factor policy', () => {
  beforeEach(() => authStore.signedOut());
  afterEach(() => vi.unstubAllGlobals());

  it('offers both routes in, rather than assuming the member has a phrase to hand', async () => {
    await heldAtPolicy();

    expect(screen.getByTestId('recovery-choose-approve')).toBeTruthy();
    expect(screen.getByTestId('recovery-choose-phrase')).toBeTruthy();
    expect(screen.queryByTestId('recovery-login')).toBeNull();
  });

  it('opens the recovery phrase when the member picks it', async () => {
    await heldAtPolicy();

    await act(async () => {
      fireEvent.click(screen.getByTestId('recovery-choose-phrase'));
    });

    expect(screen.getByTestId('recovery-login')).toBeTruthy();
  });

  it('opens the wait screen when the member picks another device', async () => {
    installRelay();
    await heldAtPolicy();

    await act(async () => {
      fireEvent.click(screen.getByTestId('recovery-choose-approve'));
    });

    expect(screen.getByTestId('device-approval-wait')).toBeTruthy();
  });

  it('keeps the recovery phrase one click from the wait screen', async () => {
    installRelay();
    await heldAtPolicy();
    await act(async () => {
      fireEvent.click(screen.getByTestId('recovery-choose-approve'));
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('device-approval-use-phrase'));
    });

    await waitFor(() => expect(screen.getByTestId('recovery-login')).toBeTruthy());
  });

  it('shows the ordinary methods again once the prompt is resolved', async () => {
    await heldAtPolicy();

    await act(async () => {
      authStore.recoveryResolved();
    });

    expect(screen.queryByTestId('recovery-choice')).toBeNull();
  });
});
