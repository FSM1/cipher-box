import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { App } from './App';
import { fakeCoreKitSession, fakeEngineClient, pageWrapper } from './test/authFakes';

/** `signedIn` renders a tab whose Core Kit session outlived the page. */
function renderAt(path: string, signedIn = false) {
  const Providers = pageWrapper(
    fakeEngineClient().client,
    fakeCoreKitSession({ loggedIn: signedIn }).session
  );
  return render(
    <Providers>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </Providers>
  );
}

describe('App routes', () => {
  it('renders the login page at the root', () => {
    renderAt('/');
    expect(screen.getByRole('heading', { name: 'CipherBox' })).toBeDefined();
  });

  it('renders the vault browser for the vault root when no node id is routed', async () => {
    renderAt('/files', true);
    expect(await screen.findByTestId('app-shell')).toBeDefined();
    expect(await screen.findByTestId('file-browser')).toBeDefined();
  });

  it('keys the vault browser on the routed node id', async () => {
    renderAt(`/files/${'0a'.repeat(16)}`, true);
    expect(await screen.findByTestId('file-browser')).toBeDefined();
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
