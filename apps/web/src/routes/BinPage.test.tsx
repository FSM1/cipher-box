import { act, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import {
  EngineRequestError,
  type BinDescriptor,
  type VaultStorageDescriptor,
} from '@cipherbox/client';
import { BinPage } from './BinPage';
import { view, ROOT_ID } from '../engine/testFakes';
import {
  binEntry as entry,
  fakeCoreKitSession,
  fakeEngineClient,
  pageWrapper,
  FAKE_VAULT_STORAGE,
} from '../test/authFakes';

const NODE = new Uint8Array(16).fill(7);
const NODE_HEX = '07'.repeat(16);

function bin(entries = [entry()], origin: BinDescriptor['origin'] = 'resolved'): BinDescriptor {
  return { entries, origin };
}

function storageWith(binRetentionDays: number): VaultStorageDescriptor {
  return {
    ...FAKE_VAULT_STORAGE,
    settings: { ...FAKE_VAULT_STORAGE.settings, binRetentionDays },
  };
}

type Overrides = Parameters<typeof fakeEngineClient>[0];

async function renderBin(overrides: Overrides = {}) {
  const engine = fakeEngineClient(overrides);
  const Providers = pageWrapper(engine.client, fakeCoreKitSession({ loggedIn: true }).session);
  await act(async () => {
    render(
      <Providers>
        <MemoryRouter initialEntries={['/bin']}>
          <BinPage />
        </MemoryRouter>
      </Providers>
    );
  });
  return engine;
}

async function click(testId: string): Promise<void> {
  await act(async () => {
    fireEvent.click(screen.getByTestId(testId));
  });
  // The destination picker chains `setFocus` into `snapshot`; one flush per hop.
  await act(async () => undefined);
}

describe('the bin route', () => {
  it('lists what the engine reported, newest deletion first', async () => {
    await renderBin({
      bin: () =>
        Promise.resolve(
          bin([
            entry({ originName: 'older', deletedAt: 1n }),
            entry({ originName: 'newer', deletedAt: 2n, node: new Uint8Array(16).fill(8) }),
          ])
        ),
    });

    expect(screen.getAllByTestId('bin-name').map((node) => node.textContent)).toEqual([
      'newer',
      'older',
    ]);
    expect(screen.getAllByTestId('bin-row')[1].dataset.node).toBe(NODE_HEX);
  });

  it('reads the bin once on route entry, since a read reaches the record plane', async () => {
    const read = vi.fn<() => Promise<BinDescriptor>>().mockResolvedValue(bin());
    await renderBin({ bin: read });

    expect(read).toHaveBeenCalledTimes(1);
  });

  it('renders a bin that was never established apart from one that read empty', async () => {
    await renderBin({ bin: () => Promise.resolve(bin([], 'defaults')) });

    expect(screen.getByTestId('bin-unestablished')).toBeTruthy();
    expect(screen.queryByTestId('bin-empty')).toBeNull();
  });

  it('reads an empty bin as empty', async () => {
    await renderBin({ bin: () => Promise.resolve(bin([])) });

    expect(screen.getByTestId('bin-empty')).toBeTruthy();
    expect(screen.queryByTestId('bin-unestablished')).toBeNull();
  });

  it('tells two entries of one name apart by the folder each came from', async () => {
    await renderBin({
      bin: () =>
        Promise.resolve(
          bin([
            entry({ originFolder: { kind: 'folder', name: 'work' } }),
            entry({
              node: new Uint8Array(16).fill(8),
              originFolder: { kind: 'folder', name: 'holiday' },
            }),
          ])
        ),
    });

    expect(screen.getAllByTestId('bin-name').map((node) => node.textContent)).toEqual([
      'notes.txt',
      'notes.txt',
    ]);
    expect(screen.getAllByTestId('bin-origin').map((node) => node.textContent)).toEqual([
      'from holiday',
      'from work',
    ]);
  });

  it('lists an entry whose origin folder is gone, in words and with the route up', async () => {
    await renderBin({
      bin: () => Promise.resolve(bin([entry({ originFolder: { kind: 'gone' } })])),
    });

    expect(screen.getByTestId('bin-origin').textContent).toBe('from a folder that is gone');
    expect(screen.getByTestId('bin-page')).toBeTruthy();
    expect(screen.getByTestId('bin-purge')).toBeTruthy();
  });

  it('takes the retention off the vault settings and never invents one', async () => {
    await renderBin({
      bin: () => Promise.resolve(bin()),
      vaultStorage: () => Promise.resolve(storageWith(7)),
    });

    expect(screen.getByTestId('bin-retention').dataset.days).toBe('7');
    expect(screen.getByTestId('bin-retention').textContent).toContain('7 days');
    expect(screen.getByTestId('bin-expires').textContent).toContain('expires');
  });

  it('dates no expiry where the vault deletes outright', async () => {
    await renderBin({
      bin: () => Promise.resolve(bin()),
      vaultStorage: () => Promise.resolve(storageWith(0)),
    });

    expect(screen.getByTestId('bin-expires').textContent).toBe('no expiry');
  });

  it('restores into the folder the entry names, and re-reads the bin', async () => {
    const read = vi
      .fn<() => Promise<BinDescriptor>>()
      .mockResolvedValueOnce(bin())
      .mockResolvedValue(bin([]));
    const engine = await renderBin({ bin: read });

    await click('bin-restore');

    expect(engine.calls.restores).toEqual([{ node: NODE, into: null }]);
    expect(read).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId('bin-empty')).toBeTruthy();
  });

  it('offers no other folder for a refusal another folder cannot repair', async () => {
    await renderBin({
      bin: () => Promise.resolve(bin()),
      restore: () => Promise.reject(new EngineRequestError('the engine is unreachable')),
    });

    await click('bin-restore');

    expect(screen.getByTestId('bin-error').textContent).toBe('the engine is unreachable');
    expect(screen.queryByTestId('bin-restore-elsewhere')).toBeNull();
  });

  it('offers another folder where the destination is gone', async () => {
    await renderBin({
      bin: () => Promise.resolve(bin()),
      restore: () =>
        Promise.reject(new EngineRequestError('the destination is gone', 'restoreTargetGone')),
    });

    await click('bin-restore');

    expect(screen.getByTestId('bin-restore-elsewhere')).toBeTruthy();
  });

  it('restores into a folder the member picked instead', async () => {
    const restore = vi
      .fn<() => Promise<{ kind: 'done' }>>()
      .mockRejectedValueOnce(new EngineRequestError('the destination is gone', 'restoreTargetGone'))
      .mockResolvedValue({ kind: 'done' });
    const engine = await renderBin({
      bin: () => Promise.resolve(bin()),
      restore,
      snapshot: () => Promise.resolve(view()),
    });

    await click('bin-restore');
    await click('bin-restore-elsewhere');
    await click('restore-confirm');

    expect(engine.calls.restores[1]).toEqual({ node: NODE, into: ROOT_ID });
    expect(screen.queryByTestId('restore-dialog')).toBeNull();
  });

  it('says a journaled command is not in the index it just read', async () => {
    await renderBin({
      bin: () => Promise.resolve(bin()),
      purge: () => Promise.resolve({ kind: 'queued', opId: 4n }),
    });

    await click('bin-purge');
    await click('purge-confirm');

    expect(screen.getByTestId('bin-queued')).toBeTruthy();
    // The row is still listed, because the published index does not carry it yet.
    expect(screen.getAllByTestId('bin-row')).toHaveLength(1);

    await click('bin-reload');
    expect(screen.queryByTestId('bin-queued')).toBeNull();
  });

  it('never carries one command refusal into the next dialog', async () => {
    await renderBin({
      bin: () => Promise.resolve(bin()),
      restore: () => Promise.reject(new EngineRequestError('the destination is gone')),
    });

    await click('bin-restore');
    expect(screen.getByTestId('bin-error')).toBeTruthy();

    await click('bin-purge');

    expect(screen.queryByTestId('dialog-error')).toBeNull();
  });

  it('confirms a purge before it dispatches one, since it cannot be undone', async () => {
    const engine = await renderBin({ bin: () => Promise.resolve(bin()) });

    await click('bin-purge');
    expect(engine.calls.purges).toHaveLength(0);

    await click('purge-confirm');
    expect(engine.calls.purges).toEqual([NODE]);
  });

  it('keeps the purge dialog up on a refusal, in the engine words', async () => {
    await renderBin({
      bin: () => Promise.resolve(bin()),
      purge: () => Promise.reject(new EngineRequestError('no bin entry', 'notBinned')),
    });

    await click('bin-purge');
    await click('purge-confirm');

    expect(screen.getByTestId('purge-dialog')).toBeTruthy();
    expect(screen.getByTestId('dialog-error').textContent).toBe('no bin entry');
    // The dialog owns the refusal it caused; the page does not repeat it.
    expect(screen.queryByTestId('bin-error')).toBeNull();
  });
});
