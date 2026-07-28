import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { App } from './App';

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>
  );
}

describe('App routes', () => {
  it('renders the login page at the root', () => {
    renderAt('/');
    expect(screen.getByRole('heading', { name: 'CipherBox' })).toBeDefined();
  });

  it('renders the vault browser for the vault root when no node id is routed', () => {
    renderAt('/files');
    expect(screen.getByTestId('files-node').textContent).toBe('root');
  });

  it('keys the vault browser on the routed node id', () => {
    renderAt('/files/0a1b2c');
    expect(screen.getByTestId('files-node').textContent).toBe('0a1b2c');
  });

  it('sends an unknown path back to login', () => {
    renderAt('/nope');
    expect(screen.getByRole('heading', { name: 'CipherBox' })).toBeDefined();
  });
});
