import type { EngineClient } from '@cipherbox/client';
import { render, screen } from '@testing-library/react';
import { StrictMode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { EngineProvider, useEngine } from './EngineProvider';

/** Counts the clients a provider builds and disposes; that is all it touches. */
function clientLedger() {
  const built: EngineClient[] = [];
  const disposed: EngineClient[] = [];
  const createClient = () => {
    const client = {
      dispose: () => {
        disposed.push(client);
        return Promise.resolve();
      },
    } as unknown as EngineClient;
    built.push(client);
    return client;
  };
  return { built, disposed, createClient };
}

function Probe({ seen }: { seen?: (EngineClient | null)[] }) {
  const client = useEngine();
  seen?.push(client);
  return <span data-testid="probe">{client ? 'ready' : 'pending'}</span>;
}

describe('EngineProvider', () => {
  it('builds exactly one engine client and hands it to consumers', () => {
    const { built, createClient } = clientLedger();
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
    const { built, disposed, createClient } = clientLedger();

    const { unmount } = render(
      <EngineProvider createClient={createClient}>
        <span />
      </EngineProvider>
    );
    expect(disposed).toEqual([]);

    unmount();
    expect(disposed).toEqual(built);
  });

  it('leaves exactly one live client after a StrictMode double-mount', () => {
    const { built, disposed, createClient } = clientLedger();

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
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      expect(() => render(<Probe />)).toThrow(/EngineProvider/);
    } finally {
      consoleError.mockRestore();
    }
  });
});
