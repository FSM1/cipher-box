import type { EngineClient, MediaService, SecretSource } from '@cipherbox/client';
import { render, renderHook, screen } from '@testing-library/react';
import { StrictMode, type ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { sharingStore } from '../stores/sharing.store';
import { EngineProvider, useEngine, useLoginSecretSource, useMediaService } from './EngineProvider';

// The real factory reads `navigator.serviceWorker`, which jsdom does not
// implement; the seam is what lets both outcomes be exercised.
const mediaControl = vi.hoisted(() => ({
  create: (): MediaService | null => null,
}));
vi.mock('../engine/createMediaService', () => ({
  createMediaService: () => mediaControl.create(),
}));

afterEach(() => {
  mediaControl.create = () => null;
});

/** A media service that records only whether it was started and disposed. */
function mediaLedger(log: string[] = []) {
  const media = {
    start: () => Promise.resolve(),
    dispose: () => {
      log.push('media');
      return Promise.resolve();
    },
  } as unknown as MediaService;
  return { media, log };
}

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

  it("drops the session's contacts and grants when the provider unmounts", () => {
    const { createClient } = clientLedger();
    const { unmount } = render(
      <EngineProvider createClient={createClient}>
        <span />
      </EngineProvider>
    );
    sharingStore.reported({
      scope: new Uint8Array(16).fill(7),
      contacts: [
        {
          identityPublicKey: new Uint8Array(33).fill(1),
        },
      ],
      ownContactCode: new Uint8Array([0xc0, 0xde]),
      state: {
        grants: [],
        grantRefusal: null,
        inviteLinkRefusal: null,
        inviteLinks: { live: false, expired: false, expiresAt: null, spent: 0 },
      },
    });

    unmount();

    // A contact names this identity's peers; it must not reach the next session.
    expect(sharingStore.getState().contacts).toEqual([]);
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

  it("hands consumers this tab's media service", () => {
    const { createClient } = clientLedger();
    const { media } = mediaLedger();
    mediaControl.create = () => media;
    const wrapper = ({ children }: { children: ReactNode }) => (
      <EngineProvider createClient={createClient}>{children}</EngineProvider>
    );

    const { result } = renderHook(() => useMediaService(), { wrapper });

    expect(result.current).toBe(media);
  });

  it('reports no media service where the browser offers no Service Worker', () => {
    const { createClient } = clientLedger();
    const wrapper = ({ children }: { children: ReactNode }) => (
      <EngineProvider createClient={createClient}>{children}</EngineProvider>
    );

    const { result } = renderHook(() => useMediaService(), { wrapper });

    expect(result.current).toBeNull();
  });

  it("disposes this tab's media service with the provider", async () => {
    const { createClient } = clientLedger();
    const { media, log } = mediaLedger();
    mediaControl.create = () => media;

    const { unmount } = render(
      <EngineProvider createClient={createClient}>
        <span />
      </EngineProvider>
    );
    unmount();

    await vi.waitFor(() => expect(log).toEqual(['media']));
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

    source.use({
      _UNSAFE_exportTssKey: () => Promise.resolve('00'.repeat(32)),
      accountId: () => 'acct01',
    });
    await expect(source.provideSecret()).resolves.toMatchObject({ accountId: 'acct01' });

    // The re-export capability dies with the client that could have used it.
    unmount();
    await expect(source.provideSecret()).rejects.toThrow(/no login session/);
  });
});
