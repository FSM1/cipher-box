import { act, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { VaultStorageDescriptor } from '@cipherbox/client';
import { ConfirmDeleteDialog } from './ConfirmDeleteDialog';
import {
  FAKE_VAULT_STORAGE,
  fakeCoreKitSession,
  fakeEngineClient,
  pageWrapper,
} from '../../test/authFakes';
import type { ListingRow } from '../../vault/listing';

const ROW: ListingRow = {
  id: new Uint8Array(16).fill(3),
  key: '03'.repeat(16),
  name: 'notes.txt',
  storedName: 'notes.txt',
  kind: 'file',
  icon: '[FILE]',
  size: '24 B',
  bytes: 24n,
  contentVersion: 1n,
  contentCid: null,
  modified: '14 Nov 2023',
  pending: 'none',
  deadLetter: false,
};

function storageWith(binRetentionDays: number): VaultStorageDescriptor {
  return {
    ...FAKE_VAULT_STORAGE,
    settings: { ...FAKE_VAULT_STORAGE.settings, binRetentionDays },
  };
}

/** Mounts the dialog over a settings read the provider holds for it. */
async function prompt(vaultStorage: () => Promise<VaultStorageDescriptor>): Promise<string> {
  const engine = fakeEngineClient({ vaultStorage });
  const Providers = pageWrapper(engine.client, fakeCoreKitSession({ loggedIn: true }).session);
  await act(async () => {
    render(
      <Providers>
        <ConfirmDeleteDialog
          rows={[ROW]}
          onClose={() => undefined}
          onConfirm={() => undefined}
          busy={false}
          error={null}
        />
      </Providers>
    );
  });
  return screen.getByTestId('delete-dialog').textContent ?? '';
}

describe('the delete confirmation', () => {
  it('says the delete cannot be undone where the vault deletes outright', async () => {
    // Retention 0 makes the delete a hard delete, with no bin entry behind it.
    expect(await prompt(() => Promise.resolve(storageWith(0)))).toContain('cannot be undone');
  });

  it('names the window the vault keeps, and claims no more than that', async () => {
    const message = await prompt(() => Promise.resolve(storageWith(7)));

    expect(message).toContain('keeps it in the bin for 7 days');
    expect(message).not.toContain('cannot be undone');
  });

  it('claims nothing at all while the settings read has not landed', async () => {
    // The prompt must never block on a read, so an unread vault promises no bin
    // and warns of no hard delete either.
    const message = await prompt(() => new Promise<VaultStorageDescriptor>(() => undefined));

    expect(message).toContain('delete "notes.txt"?');
    expect(message).not.toContain('cannot be undone');
    expect(message).not.toContain('bin');
  });
});
