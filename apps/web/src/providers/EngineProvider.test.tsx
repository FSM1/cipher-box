import type { EngineClient, SecretSource } from '@cipherbox/client';
import { render, renderHook, screen } from '@testing-library/react';
import { StrictMode, type ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { EngineProvider, useEngine, useLoginSecretSource } from './EngineProvider';

/** Counts the clients a provider builds and disposes; that is all it touches. */
function clientLedger() {
  const built: EngineClient[] = [];
  const disposed: EngineClient[] = [];
  const sources: SecretSource[] = [];
  const subscriptions = { open: 0 };
  const createClient = (secretSource: SecretSource) => {
    sources.push(secretSource);
    const client = {
      facade: {
        subscribe: () => {
          subscriptions.open += 1;
          return () => (subscriptions.open -= 1);
        },
      },
      dispose: () => {
        disposed.push(client);
        return Promise.resolve();
      },
    } as unknown as EngineClient;
    built.push(client);
    return client;
  };
  return { built, disposed, sources, subscriptions, createClient };
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

  it('disposes the client and its snapshot store when the provider unmounts', () => {
    const { built, disposed, subscriptions, createClient } = clientLedger();

    const { unmount } = render(
      <EngineProvider createClient={createClient}>
        <span />
      </EngineProvider>
    );
    expect(disposed).toEqual([]);
    expect(subscriptions.open).toBe(1);

    unmount();
    expect(disposed).toEqual(built);
    expect(subscriptions.open).toBe(0);
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

  it('gives the client a secret source that stops re-exporting once unmounted', async () => {
    const { sources, createClient } = clientLedger();
    const wrapper = ({ children }: { children: ReactNode }) => (
      <EngineProvider createClient={createClient}>{children}</EngineProvider>
    );

    const { result, unmount } = renderHook(() => useLoginSecretSource(), { wrapper });
    const source = result.current!;
    expect(sources).toEqual([source]);

    source.use({ _UNSAFE_exportTssKey: () => Promise.resolve('00'.repeat(32)) });
    await expect(source.provideSecret()).resolves.toBeInstanceOf(ArrayBuffer);

    // The re-export capability dies with the client that could have used it.
    unmount();
    await expect(source.provideSecret()).rejects.toThrow(/no login session/);
  });
});
