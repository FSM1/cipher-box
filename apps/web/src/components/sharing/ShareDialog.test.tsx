import type { ReactNode } from 'react';
import { EngineRequestError, toHex } from '@cipherbox/client';
import type { EngineClient, EventDescriptor } from '@cipherbox/client';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EngineProvider } from '../../providers/EngineProvider';
import { sharingStore, type VerifiedContact } from '../../stores/sharing.store';
import type { ListingRow } from '../../vault/listing';
import { ShareDialog } from './ShareDialog';

const DOCS = new Uint8Array(16).fill(7);
const PHOTOS = new Uint8Array(16).fill(9);
const CODE_HEX = '00ff10';

const folder: ListingRow = {
  id: DOCS,
  key: toHex(DOCS),
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

/** The grant surface the dialog drives; a named command answers with a refusal. */
function sharingEngine(refusals: Record<string, Error> = {}) {
  const answer = <T,>(name: string, value: T) =>
    refusals[name] === undefined ? Promise.resolve(value) : Promise.reject(refusals[name]);

  const facade = {
    subscribe: (_listener: (event: EventDescriptor) => void) => () => undefined,
    snapshot: () => new Promise<never>(() => undefined),
    setFocus: () => Promise.resolve(),
    importContact: vi.fn((code: Uint8Array) =>
      answer('importContact', {
        kind: 'contactImported' as const,
        identityPublicKey: new Uint8Array(33).fill(code[0] ?? 1),
        encPublicKey: new Uint8Array(32).fill(1),
      })
    ),
    grant: vi.fn(() => answer('grant', { kind: 'done' as const })),
    revoke: vi.fn(() => answer('revoke', { kind: 'done' as const })),
    downgrade: vi.fn(() => answer('downgrade', { kind: 'done' as const })),
  };

  const client = {
    facade,
    reportFocus: () => undefined,
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;

  return { client, facade };
}

function share(engine = sharingEngine()) {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <EngineProvider createClient={() => engine.client}>{children}</EngineProvider>
  );
  render(wrapper({ children: <ShareDialog row={folder} onClose={() => undefined} /> }));
  return engine;
}

/** Clicks and lets the command it dispatched settle. */
async function click(testId: string) {
  await act(async () => {
    fireEvent.click(screen.getByTestId(testId));
  });
}

afterEach(() => sharingStore.clear());

describe('the grant list', () => {
  it('says only that this session recorded no grant, never that none exists', () => {
    share();

    expect(screen.getByTestId('share-no-grants')).toBeTruthy();
    expect(screen.getByTestId('share-session-note')).toBeTruthy();
    expect(screen.queryByTestId('share-grant-list')).toBeNull();
  });

  it('lists one row per grant standing on this scope, and none from another', () => {
    const alice = contact(1);
    const bob = contact(2);
    sharingStore.granted(DOCS, alice, 'write');
    sharingStore.granted(PHOTOS, bob, 'read');
    share();

    const rows = screen.getAllByTestId('share-grant-row');
    expect(rows).toHaveLength(1);
    expect(rows[0].textContent).toContain(alice.key);
  });

  it('leaves no grant row once the engine accepted the revoke', async () => {
    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'read');
    const engine = share();

    await click('share-revoke');

    expect(engine.facade.revoke).toHaveBeenCalledWith(DOCS, alice.identityPublicKey);
    expect(screen.queryByTestId('share-grant-row')).toBeNull();
    expect(screen.getByTestId('share-no-grants')).toBeTruthy();
  });

  it('renders a downgrade as the row changing permission, not as a revoke', async () => {
    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'write');
    const engine = share();

    await click('share-downgrade');

    expect(engine.facade.downgrade).toHaveBeenCalledWith(DOCS, alice.identityPublicKey);
    expect(screen.getAllByTestId('share-grant-row')).toHaveLength(1);
    expect(screen.getByTestId('share-grant-permission').textContent).toBe('read');
    // Read is the floor a downgrade lands on, so the control is spent.
    expect(screen.queryByTestId('share-downgrade')).toBeNull();
  });

  it('keeps the write grant a refused downgrade left standing, and says why', async () => {
    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'write');
    share(sharingEngine({ downgrade: new EngineRequestError('the publish was refused') }));

    await click('share-downgrade');

    expect(screen.getByTestId('share-grant-permission').textContent).toBe('write');
    expect(screen.getByTestId('dialog-error').textContent).toBe('the publish was refused');
  });
});

describe('granting', () => {
  it('grants the picked contact at the picked permission', async () => {
    const alice = contact(1);
    const engine = share();

    fireEvent.change(screen.getByLabelText('contact'), { target: { value: alice.key } });
    fireEvent.change(screen.getByLabelText('permission'), { target: { value: 'write' } });
    await click('share-grant');

    expect(engine.facade.grant).toHaveBeenCalledWith(DOCS, alice.identityPublicKey, 'write');
    expect(screen.getByTestId('share-grant-permission').textContent).toBe('write');
  });

  it('lists no row for a grant the engine refused', async () => {
    const alice = contact(1);
    share(sharingEngine({ grant: new EngineRequestError('the recipient is the owner') }));

    fireEvent.change(screen.getByLabelText('contact'), { target: { value: alice.key } });
    await click('share-grant');

    expect(screen.queryByTestId('share-grant-row')).toBeNull();
    expect(screen.getByTestId('dialog-error').textContent).toBe('the recipient is the owner');
  });

  it('cannot grant to a contact that already holds a grant here', () => {
    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'read');
    share();

    expect(screen.getByTestId('share-no-contacts')).toBeTruthy();
    expect((screen.getByTestId('share-grant') as HTMLButtonElement).disabled).toBe(true);
  });
});

describe('the import step', () => {
  async function openImport(engine = sharingEngine()) {
    share(engine);
    await click('share-import-contact');
    return engine;
  }

  it('hands the engine the pasted code as bytes and comes back with the contact', async () => {
    const engine = await openImport();

    fireEvent.change(screen.getByLabelText('contact code'), { target: { value: CODE_HEX } });
    await click('import-contact-confirm');

    expect(engine.facade.importContact).toHaveBeenCalledWith(new Uint8Array([0x00, 0xff, 0x10]));
    await waitFor(() => expect(screen.getByTestId('share-dialog')).toBeTruthy());
    expect(screen.getByLabelText('contact')).toBeTruthy();
  });

  it('refuses to send a paste that is not a code, without calling it unverified', async () => {
    const engine = await openImport();

    fireEvent.change(screen.getByLabelText('contact code'), { target: { value: 'not a code' } });

    expect(screen.getByTestId('import-contact-unreadable')).toBeTruthy();
    expect((screen.getByTestId('import-contact-confirm') as HTMLButtonElement).disabled).toBe(true);
    expect(engine.facade.importContact).not.toHaveBeenCalled();
  });

  it("shows the engine's refusal for a code whose binding did not verify", async () => {
    const refusal = new EngineRequestError('contact-code-binding refused', 'trustViolation');
    await openImport(sharingEngine({ importContact: refusal }));

    fireEvent.change(screen.getByLabelText('contact code'), { target: { value: CODE_HEX } });
    await click('import-contact-confirm');

    expect(screen.getByTestId('dialog-error').textContent).toBe('contact-code-binding refused');
    expect(screen.getByTestId('import-contact-form')).toBeTruthy();
    expect(sharingStore.getState().contacts).toEqual([]);
  });

  it('retires the import refusal when the step it belongs to is left', async () => {
    const refusal = new EngineRequestError('contact-code-binding refused', 'trustViolation');
    await openImport(sharingEngine({ importContact: refusal }));
    fireEvent.change(screen.getByLabelText('contact code'), { target: { value: CODE_HEX } });
    await click('import-contact-confirm');

    await click('import-contact-cancel');

    expect(screen.getByTestId('share-dialog')).toBeTruthy();
    expect(screen.queryByTestId('dialog-error')).toBeNull();
  });
});
