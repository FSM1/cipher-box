import { act, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { VaultStorageDescriptor } from '@cipherbox/client';
import { useVaultStorage } from './VaultStorageProvider';
import {
  FAKE_VAULT_STORAGE,
  fakeCoreKitSession,
  fakeEngineClient,
  pageWrapper,
} from '../test/authFakes';

/** Reads the held value the way `/bin` and the delete prompt both do. */
function Probe() {
  const { storage } = useVaultStorage();
  return <span data-testid="probe">{storage?.settings.binRetentionDays ?? 'unread'}</span>;
}

describe('the vault storage provider', () => {
  it('holds one read for every surface that states what the vault actuates', async () => {
    const read = vi
      .fn<() => Promise<VaultStorageDescriptor>>()
      .mockResolvedValue(FAKE_VAULT_STORAGE);
    const engine = fakeEngineClient({ vaultStorage: read });
    const Providers = pageWrapper(engine.client, fakeCoreKitSession({ loggedIn: true }).session);
    await act(async () => {
      render(
        <Providers>
          <Probe />
          <Probe />
        </Providers>
      );
    });

    expect(screen.getAllByTestId('probe').map((node) => node.textContent)).toEqual(['30', '30']);
    expect(read).toHaveBeenCalledTimes(1);
  });

  it('reads the settings again when the engine adopts a change', async () => {
    const read = vi
      .fn<() => Promise<VaultStorageDescriptor>>()
      .mockResolvedValueOnce(FAKE_VAULT_STORAGE)
      .mockResolvedValue({
        ...FAKE_VAULT_STORAGE,
        settings: { ...FAKE_VAULT_STORAGE.settings, binRetentionDays: 0 },
      });
    const engine = fakeEngineClient({ vaultStorage: read });
    const Providers = pageWrapper(engine.client, fakeCoreKitSession({ loggedIn: true }).session);
    await act(async () => {
      render(
        <Providers>
          <Probe />
        </Providers>
      );
    });
    expect(screen.getByTestId('probe').textContent).toBe('30');

    // The member turned the bin off on another device, and the focus tick
    // adopted it: what this tab states about a delete has to follow.
    await act(async () => {
      engine.emit({ kind: 'vaultSettingsChanged' });
    });

    expect(screen.getByTestId('probe').textContent).toBe('0');
    expect(read).toHaveBeenCalledTimes(2);
  });

  it('leaves the held read alone for an event that is not a settings change', async () => {
    const read = vi
      .fn<() => Promise<VaultStorageDescriptor>>()
      .mockResolvedValue(FAKE_VAULT_STORAGE);
    const engine = fakeEngineClient({ vaultStorage: read });
    const Providers = pageWrapper(engine.client, fakeCoreKitSession({ loggedIn: true }).session);
    await act(async () => {
      render(
        <Providers>
          <Probe />
        </Providers>
      );
    });

    await act(async () => {
      engine.emit({ kind: 'snapshotUpdated' });
    });

    expect(read).toHaveBeenCalledTimes(1);
  });

  it('rejects a consumer mounted outside the provider', () => {
    // A surface that reads no provider would claim the least for ever, and no
    // test would catch the missing wiring.
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      expect(() => render(<Probe />)).toThrow(/VaultStorageProvider/);
    } finally {
      consoleError.mockRestore();
    }
  });
});
