import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it } from 'vitest';
import { App } from './App';
import { authStore } from './stores/auth.store';
import { fakeCoreKitSession, fakeEngineClient, pageWrapper } from './test/authFakes';

function renderAt(path: string) {
  const Providers = pageWrapper(fakeEngineClient().client, fakeCoreKitSession().session);
  return render(
    <Providers>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </Providers>
  );
}

afterEach(() => authStore.signedOut());

describe('App routes', () => {
  it('renders the login page at the root', () => {
    renderAt('/');
    expect(screen.getByRole('heading', { name: 'CipherBox' })).toBeDefined();
  });

  it('renders the vault browser for the vault root when no node id is routed', () => {
    authStore.signedIn('google', 'user@example.test');
    renderAt('/files');
    expect(screen.getByTestId('app-shell')).toBeDefined();
    expect(screen.getByTestId('file-browser')).toBeDefined();
  });

  it('keys the vault browser on the routed node id', () => {
    authStore.signedIn('google', 'user@example.test');
    renderAt(`/files/${'0a'.repeat(16)}`);
    expect(screen.getByTestId('file-browser')).toBeDefined();
  });

  it('sends a signed-out tab away from the vault browser', async () => {
    renderAt('/files');
    // The redirect waits on the Core Kit restore: a tab that is still deciding
    // must not be thrown out of its own vault.
    expect(await screen.findByRole('heading', { name: 'CipherBox' })).toBeDefined();
  });

  it('sends an unknown path back to login', () => {
    renderAt('/nope');
    expect(screen.getByRole('heading', { name: 'CipherBox' })).toBeDefined();
  });
});
