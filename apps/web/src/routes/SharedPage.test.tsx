import { act, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { ReceivedShareDescriptor, ReceivedShareResolution } from '@cipherbox/client';
import { SharedPage } from './SharedPage';
import { fakeCoreKitSession, fakeEngineClient, pageWrapper } from '../test/authFakes';

const SHARER = new Uint8Array(33).fill(0xa1);
const SHARER_HEX = 'a1'.repeat(33);

function share(
  index: number,
  resolution: ReceivedShareResolution | null,
  displayName = `folder-${index}`
): ReceivedShareDescriptor {
  return {
    scope: new Uint8Array(16).fill(index),
    sharerIdentityPublicKey: SHARER,
    displayName,
    permission: 'read',
    resolution,
  };
}

async function renderShared(receivedShares?: () => Promise<ReceivedShareDescriptor[]>) {
  const engine = fakeEngineClient(receivedShares === undefined ? {} : { receivedShares });
  const Providers = pageWrapper(engine.client, fakeCoreKitSession({ loggedIn: true }).session);
  await act(async () => {
    render(
      <Providers>
        <MemoryRouter initialEntries={['/shared']}>
          <SharedPage />
        </MemoryRouter>
      </Providers>
    );
  });
  return engine;
}

function standings(): { resolution: string | undefined; tone: string | undefined }[] {
  return screen
    .getAllByTestId('shared-standing')
    .map((node) => ({ resolution: node.dataset.resolution, tone: node.dataset.tone }));
}

describe('the shared route', () => {
  it('lists what the engine reported, with the permission the accept committed', async () => {
    await renderShared(() =>
      Promise.resolve([
        { ...share(1, 'granted', 'photos'), permission: 'write' },
        share(2, 'granted', 'invoices'),
      ])
    );

    expect(screen.getAllByTestId('shared-row')).toHaveLength(2);
    expect(screen.getAllByTestId('shared-name').map((node) => node.textContent)).toEqual([
      'photos',
      'invoices',
    ]);
    expect(screen.getAllByTestId('shared-permission').map((node) => node.textContent)).toEqual([
      'write',
      'read',
    ]);
    expect(screen.getAllByTestId('shared-sharer')[0].textContent).toBe(SHARER_HEX);
  });

  it('paints a revocation signal as a removal in the warning class', async () => {
    await renderShared(() => Promise.resolve([share(1, 'revocation-signal')]));

    expect(standings()).toEqual([{ resolution: 'revocation-signal', tone: 'warning' }]);
  });

  it('keeps epoch lag and an unresolvable name out of the warning class', async () => {
    // Neither is a removal, so neither may read as one.
    await renderShared(() => Promise.resolve([share(1, 'epoch-lag'), share(2, 'unresolvable')]));

    expect(standings()).toEqual([
      { resolution: 'epoch-lag', tone: 'pending' },
      { resolution: 'unresolvable', tone: 'pending' },
    ]);
  });

  it('never paints a share no pass has resolved as granted', async () => {
    await renderShared(() => Promise.resolve([share(1, null)]));

    expect(standings()).toEqual([{ resolution: 'none', tone: 'pending' }]);
  });

  it('fails closed on a standing this build cannot name', async () => {
    // A class the engine gains ahead of this build must never read as granted.
    const unknown = 'scope-sealed' as ReceivedShareResolution;
    await renderShared(() => Promise.resolve([share(1, unknown)]));

    expect(standings()).toEqual([{ resolution: 'scope-sealed', tone: 'warning' }]);
  });

  it('tells a list it has not read apart from an empty one', async () => {
    await renderShared(() => new Promise(() => undefined));

    expect(screen.getByTestId('shared-unread')).toBeTruthy();
    expect(screen.queryByTestId('shared-empty')).toBeNull();
  });

  it('reports an empty list once one lands, and offers no browse over nothing', async () => {
    await renderShared();

    expect(screen.getByTestId('shared-empty')).toBeTruthy();
    expect(screen.queryByTestId('shared-unread')).toBeNull();
    expect(screen.queryAllByTestId('shared-open')).toHaveLength(0);
  });

  it('opens a received share in the vault browser, at its own scope root', async () => {
    await renderShared(() => Promise.resolve([share(1, 'granted', 'photos')]));

    const open = screen.getByTestId('shared-open');
    expect(open.getAttribute('href')).toBe(`/files/${'01'.repeat(16)}`);
    expect(open.getAttribute('aria-label')).toBe('open photos');
  });

  it('keeps two sharers that claim one scope id apart', async () => {
    // A sharer authors its own scope id, so the engine keys a bookmark on the
    // pair. React only warns on a duplicate key, so the warning is the
    // assertion: a row keyed on the scope alone collides here.
    const other = new Uint8Array(33).fill(0xb2);
    const errors: unknown[][] = [];
    const spy = vi.spyOn(console, 'error').mockImplementation((...args) => {
      errors.push(args);
    });
    try {
      await renderShared(() =>
        Promise.resolve([
          share(1, 'granted', 'theirs'),
          { ...share(1, 'granted', 'also-theirs'), sharerIdentityPublicKey: other },
        ])
      );
    } finally {
      spy.mockRestore();
    }

    expect(screen.getAllByTestId('shared-row')).toHaveLength(2);
    expect(screen.getAllByTestId('shared-name').map((node) => node.textContent)).toEqual([
      'theirs',
      'also-theirs',
    ]);
    expect(errors.filter((args) => String(args[0]).includes('same key'))).toEqual([]);
  });

  it('still offers the browse on a revoked share, over the listing that stands', async () => {
    // The removal is discovered, not delivered: what a member last saw is still
    // theirs to read.
    await renderShared(() => Promise.resolve([share(1, 'revocation-signal')]));

    expect(screen.getByTestId('shared-open').getAttribute('href')).toBe(
      `/files/${'01'.repeat(16)}`
    );
  });

  it("renders the engine's own words when the read is refused, and lists nothing", async () => {
    await renderShared(() => Promise.reject(new Error('the accepted list did not open')));

    expect(screen.getByTestId('shared-error').textContent).toBe('the accepted list did not open');
    expect(screen.queryByTestId('shared-list')).toBeNull();
    expect(screen.queryByTestId('shared-empty')).toBeNull();
    // The refusal is the answer; a second note saying nothing was read repeats it.
    expect(screen.queryByTestId('shared-unread')).toBeNull();
  });

  it('re-reads on demand, so a standing moves without a reload', async () => {
    let resolution: ReceivedShareResolution = 'granted';
    await renderShared(() => Promise.resolve([share(1, resolution)]));
    expect(standings()).toEqual([{ resolution: 'granted', tone: 'ok' }]);

    resolution = 'revocation-signal';
    await act(async () => {
      fireEvent.click(screen.getByTestId('shared-reload'));
    });

    expect(standings()).toEqual([{ resolution: 'revocation-signal', tone: 'warning' }]);
  });
});
