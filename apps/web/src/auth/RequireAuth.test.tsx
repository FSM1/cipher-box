import { EngineHeldElsewhereError } from '@cipherbox/client';
import { resetLoginFlowLatches } from '@cipherbox/login';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, expect, it } from 'vitest';
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
    const core = fakeCoreKitSession({ loggedIn: true });
    core.session._UNSAFE_exportTssKey = () => Promise.reject(new Error(REFUSAL));
    mount(core, fakeEngineClient(), watcher);

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

it('shows only the host and status of a refused provider response', async () => {
  const core = fakeCoreKitSession({ loggedIn: true });
  core.session._UNSAFE_exportTssKey = () =>
    Promise.reject({
      url: 'https://node-1.dev-node.web3auth.io/rss?token=private-token',
      status: 500,
      body: 'private-body',
    });
  mount(core);

  await screen.findByTestId('sign-in-methods');
  expect(screen.getByRole('alert').textContent).toBe(
    'the request to node-1.dev-node.web3auth.io failed with status 500'
  );
  expect(JSON.stringify(authStore.getState())).not.toContain('private-');
});

it('clears the restore refusal when the member signs in again', async () => {
  const core = fakeCoreKitSession({ loggedIn: true });
  const exportSecret = core.session._UNSAFE_exportTssKey;
  core.session._UNSAFE_exportTssKey = () => Promise.reject(new Error(REFUSAL));
  mount(core);
  await screen.findByTestId('sign-in-methods');
  expect(screen.getByRole('alert').textContent).toBe(REFUSAL);

  core.session._UNSAFE_exportTssKey = exportSecret;
  await signInByEmail();

  await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
  expect(authStore.getState().method).toBe('email');
});
