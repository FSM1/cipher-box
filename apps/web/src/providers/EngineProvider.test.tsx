import type { EngineClient } from '@cipherbox/client';
import { render, screen } from '@testing-library/react';
import { StrictMode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { EngineProvider, useEngine } from './EngineProvider';

/** The provider only builds, exposes and disposes the client — this is all it touches. */
function fakeClient(disposed: string[], id: string): EngineClient {
  return {
    dispose: () => {
      disposed.push(id);
      return Promise.resolve();
    },
  } as unknown as EngineClient;
}

function Probe({ seen }: { seen: (EngineClient | null)[] }) {
  const client = useEngine();
  seen.push(client);
  return <span data-testid="probe">{client ? 'ready' : 'pending'}</span>;
}

describe('EngineProvider', () => {
  it('builds exactly one engine client and hands it to consumers', () => {
    const built: EngineClient[] = [];
    const disposed: string[] = [];
    const createClient = () => {
      const client = fakeClient(disposed, `client-${String(built.length)}`);
      built.push(client);
      return client;
    };
    const seen: (EngineClient | null)[] = [];

    render(
      <EngineProvider createClient={createClient}>
        <Probe seen={seen} />
      </EngineProvider>
    );

    expect(built).toHaveLength(1);
    expect(screen.getByTestId('probe').textContent).toBe('ready');
    expect(seen.at(-1)).toBe(built[0]);
  });

  it('disposes the client when the provider unmounts', () => {
    const disposed: string[] = [];
    const createClient = () => fakeClient(disposed, 'only');

    const { unmount } = render(
      <EngineProvider createClient={createClient}>
        <span />
      </EngineProvider>
    );
    expect(disposed).toEqual([]);

    unmount();
    expect(disposed).toEqual(['only']);
  });

  it('leaves exactly one live client after a StrictMode double-mount', () => {
    const built: EngineClient[] = [];
    const disposed: string[] = [];
    const createClient = () => {
      const id = `client-${String(built.length)}`;
      const client = fakeClient(disposed, id);
      built.push(client);
      return client;
    };

    render(
      <StrictMode>
        <EngineProvider createClient={createClient}>
          <span />
        </EngineProvider>
      </StrictMode>
    );

    expect(built.length - disposed.length).toBe(1);
  });

  it('rejects a consumer mounted outside the provider', () => {
    const seen: (EngineClient | null)[] = [];
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      expect(() => render(<Probe seen={seen} />)).toThrow(/EngineProvider/);
    } finally {
      consoleError.mockRestore();
    }
  });
});
