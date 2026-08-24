import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { SharingActions } from '../../hooks/useSharingActions';
import { sharingStore, type VerifiedContact } from '../../sharing/sharingStore';
import type { ListingRow } from '../../vault/listing';
import { ImportContactDialog } from './ImportContactDialog';
import { ShareDialog } from './ShareDialog';

const DOCS = new Uint8Array(16).fill(7);

const folder: ListingRow = {
  id: DOCS,
  key: '07'.repeat(16),
  name: 'docs',
  kind: 'folder',
  icon: '[DIR]',
  size: '-',
  bytes: null,
  contentVersion: null,
  modified: '-',
  pending: 'none',
  deadLetter: false,
};

function contact(seed: number): VerifiedContact {
  return sharingStore.contactImported({
    kind: 'contactImported',
    identityPublicKey: new Uint8Array(33).fill(seed),
    encPublicKey: new Uint8Array(32).fill(seed),
  });
}

function actions(overrides: Partial<SharingActions> = {}): SharingActions {
  return {
    busy: null,
    failure: null,
    importContact: vi.fn(() => Promise.resolve(true)),
    grant: vi.fn(() => Promise.resolve(true)),
    revoke: vi.fn(() => Promise.resolve(true)),
    downgrade: vi.fn(() => Promise.resolve(true)),
    ...overrides,
  };
}

function share(current = actions()) {
  render(
    <ShareDialog
      row={folder}
      actions={current}
      onImportContact={() => undefined}
      onClose={() => undefined}
    />
  );
  return current;
}

afterEach(() => sharingStore.clear());

describe('ShareDialog', () => {
  it('shows a folder nothing has been granted on as shared with no one', () => {
    share();

    expect(screen.getByTestId('share-no-grants')).toBeTruthy();
    expect(screen.queryByTestId('share-grant-list')).toBeNull();
  });

  it('lists one row per grant standing on this scope, and none from another', () => {
    const alice = contact(1);
    const bob = contact(2);
    sharingStore.granted(DOCS, alice, 'write');
    sharingStore.granted(new Uint8Array(16).fill(9), bob, 'read');
    share();

    const rows = screen.getAllByTestId('share-grant-row');
    expect(rows).toHaveLength(1);
    expect(rows[0].textContent).toContain(alice.key);
  });

  it('leaves no grant row once the engine revoked it', async () => {
    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'read');
    const current = share();

    fireEvent.click(screen.getByTestId('share-revoke'));
    await act(async () => {
      sharingStore.revoked(DOCS, alice);
    });

    expect(current.revoke).toHaveBeenCalledWith(DOCS, alice);
    expect(screen.queryByTestId('share-grant-row')).toBeNull();
    expect(screen.getByTestId('share-no-grants')).toBeTruthy();
  });

  it('renders a downgrade as the row changing permission, not as a revoke', async () => {
    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'write');
    const current = share();

    fireEvent.click(screen.getByTestId('share-downgrade'));
    await act(async () => {
      sharingStore.downgraded(DOCS, alice);
    });

    expect(current.downgrade).toHaveBeenCalledWith(DOCS, alice);
    expect(screen.getAllByTestId('share-grant-row')).toHaveLength(1);
    expect(screen.getByTestId('share-grant-permission').textContent).toBe('read');
    // Read is the floor a downgrade lands on, so the control is spent.
    expect(screen.queryByTestId('share-downgrade')).toBeNull();
  });

  it('grants the picked contact at the picked permission', async () => {
    const alice = contact(1);
    const current = share();

    fireEvent.change(screen.getByLabelText('contact'), { target: { value: alice.key } });
    fireEvent.change(screen.getByLabelText('permission'), { target: { value: 'write' } });
    await act(async () => {
      fireEvent.click(screen.getByTestId('share-grant'));
    });

    expect(current.grant).toHaveBeenCalledWith(DOCS, alice, 'write');
  });

  it('cannot grant to a contact that already holds a grant here', () => {
    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'read');
    share();

    expect(screen.getByTestId('share-no-contacts')).toBeTruthy();
    expect((screen.getByTestId('share-grant') as HTMLButtonElement).disabled).toBe(true);
  });

  it('reports a refused grant in the engine’s words', () => {
    contact(1);
    share(actions({ failure: { command: 'grant', message: 'the recipient is the owner' } }));

    expect(screen.getByTestId('dialog-error').textContent).toBe('the recipient is the owner');
  });

  it('leaves an import refusal to the import step', () => {
    contact(1);
    share(actions({ failure: { command: 'importContact', message: 'binding did not verify' } }));

    expect(screen.queryByTestId('dialog-error')).toBeNull();
  });
});

describe('ImportContactDialog', () => {
  function importDialog(overrides: Partial<Parameters<typeof ImportContactDialog>[0]> = {}) {
    const onConfirm = vi.fn();
    render(
      <ImportContactDialog
        busy={false}
        error={null}
        onClose={() => undefined}
        onConfirm={onConfirm}
        {...overrides}
      />
    );
    return onConfirm;
  }

  it('hands the engine the pasted code as bytes', () => {
    const onConfirm = importDialog();

    fireEvent.change(screen.getByLabelText('contact code'), { target: { value: '00ff10' } });
    fireEvent.click(screen.getByTestId('import-contact-confirm'));

    expect(onConfirm).toHaveBeenCalledWith(new Uint8Array([0x00, 0xff, 0x10]));
  });

  it('refuses to send a paste that is not a code, without calling it unverified', () => {
    const onConfirm = importDialog();

    fireEvent.change(screen.getByLabelText('contact code'), { target: { value: 'not a code' } });

    expect(screen.getByTestId('import-contact-unreadable')).toBeTruthy();
    expect((screen.getByTestId('import-contact-confirm') as HTMLButtonElement).disabled).toBe(true);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("shows the engine's refusal for a code whose binding did not verify", () => {
    importDialog({ error: 'contact-code-binding refused' });

    expect(screen.getByTestId('dialog-error').textContent).toBe('contact-code-binding refused');
    expect(screen.queryByTestId('import-contact-unreadable')).toBeNull();
  });
});
