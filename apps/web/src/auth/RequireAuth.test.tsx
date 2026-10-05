import { EngineHeldElsewhereError } from '@cipherbox/client';
import { resetLoginFlowLatches } from '@cipherbox/login';
import { act, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { SignInPanel } from '../components/auth/SignInPanel';
import { authStore } from '../stores/auth.store';
import {
  fakeCoreKitSession,
  fakeEngineClient,
  pageWrapper,
  signInByEmail,
} from '../test/authFakes';
import { RequireAuth } from './RequireAuth';
import { SessionEndWatcher } from './SessionEndWatcher';

const REFUSAL = 'master poly commits inconsistent with tssPubKey';

beforeEach(() => {
  resetLoginFlowLatches();
  authStore.signedOut();
});

afterEach(() => vi.useRealTimers());

async function exhaustRestoreRetries(): Promise<void> {
  await act(async () => {});
  await act(() => vi.runAllTimersAsync());
  vi.useRealTimers();
}

function mount(
  core: ReturnType<typeof fakeCoreKitSession>,
  engine = fakeEngineClient(),
  watcher = true
) {
  render(
    <MemoryRouter initialEntries={['/files']}>
      {watcher && <SessionEndWatcher />}
      <Routes>
        <Route
          path="/files"
          element={
            <RequireAuth>
              <div>vault</div>
            </RequireAuth>
          }
        />
        <Route path="/" element={<SignInPanel />} />
      </Routes>
    </MemoryRouter>,
    { wrapper: pageWrapper(engine.client, core.session) }
  );
}

it.each([true, false])(
  'preserves a refused restore across routing with watcher=%s',
  async (watcher) => {
    vi.useFakeTimers();
    const core = fakeCoreKitSession({ loggedIn: true });
    core.session._UNSAFE_exportTssKey = () => Promise.reject(new Error(REFUSAL));
    mount(core, fakeEngineClient(), watcher);
    await exhaustRestoreRetries();

    await screen.findByTestId('sign-in-methods');
    expect(screen.getByRole('alert').textContent).toBe(REFUSAL);
    expect(core.calls.logouts).toBe(1);
    expect(screen.queryByText('vault')).toBeNull();
  }
);

it('preserves the account-conflict explanation on the front door', async () => {
  const core = fakeCoreKitSession({ loggedIn: true });
  const engine = fakeEngineClient({
    start: () => Promise.reject(new EngineHeldElsewhereError(null)),
  });
  mount(core, engine);

  await screen.findByTestId('sign-in-methods');
  expect(screen.getByRole('alert').textContent).toContain('sign out in that tab');
  expect(core.calls.logouts).toBe(1);
});

it('carries a refused provider response from the restore to the front door', async () => {
  vi.useFakeTimers();
  const core = fakeCoreKitSession({ loggedIn: true });
  core.session._UNSAFE_exportTssKey = () =>
    Promise.reject({
      url: 'https://node-1.dev-node.web3auth.io/rss?token=private-token',
      status: 500,
      body: 'private-body',
    });
  mount(core);
  await exhaustRestoreRetries();

  await screen.findByTestId('sign-in-methods');
  expect(screen.getByRole('alert').textContent).toBe(
    'the request to node-1.dev-node.web3auth.io failed with status 500'
  );
  expect(JSON.stringify(authStore.getState())).not.toContain('private-');
});

it('clears the restore refusal when the member signs in again', async () => {
  vi.useFakeTimers();
  const core = fakeCoreKitSession({ loggedIn: true });
  const exportSecret = core.session._UNSAFE_exportTssKey;
  core.session._UNSAFE_exportTssKey = () => Promise.reject(new Error(REFUSAL));
  mount(core);
  await exhaustRestoreRetries();
  await screen.findByTestId('sign-in-methods');
  expect(screen.getByRole('alert').textContent).toBe(REFUSAL);

  core.session._UNSAFE_exportTssKey = exportSecret;
  await signInByEmail();

  await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
  expect(authStore.getState().method).toBe('email');
});

it('keeps the vault route through a transient refusal and restores without another login', async () => {
  vi.useFakeTimers();
  const core = fakeCoreKitSession({ loggedIn: true });
  const engine = fakeEngineClient();
  const exportSecret = vi.spyOn(core.session, '_UNSAFE_exportTssKey');
  exportSecret.mockRejectedValueOnce(new Error(REFUSAL));
  mount(core, engine);

  await act(() => vi.advanceTimersByTimeAsync(14_999));
  expect(exportSecret).toHaveBeenCalledTimes(1);
  expect(core.calls.logouts).toBe(0);
  expect(engine.calls.started).toHaveLength(0);
  expect(screen.queryByTestId('sign-in-methods')).toBeNull();

  await exhaustRestoreRetries();
  expect(engine.calls.started).toHaveLength(1);
  expect(exportSecret).toHaveBeenCalledTimes(2);
  expect(core.calls.logouts).toBe(0);
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.queryByTestId('sign-in-methods')).toBeNull();
});
