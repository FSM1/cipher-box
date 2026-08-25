import type { ReactNode } from 'react';
import { EngineRequestError, toHex } from '@cipherbox/client';
import type {
  EngineClient,
  EventDescriptor,
  Permission,
  SharingDescriptor,
} from '@cipherbox/client';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EngineProvider } from '../../providers/EngineProvider';
import { sharingStore } from '../../stores/sharing.store';
import type { ListingRow } from '../../vault/listing';
import { ShareDialog } from './ShareDialog';

const DOCS = new Uint8Array(16).fill(7);
const CODE_HEX = '00ff10';

/** Stands in for the engine's opaque capability; the UI reads none of it. */
const MINTED_FRAGMENT = 'a-minted-fragment';

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

function identity(seed: number): Uint8Array {
  return new Uint8Array(33).fill(seed);
}

function key(seed: number): string {
  return toHex(identity(seed));
}

/** The sharing state one vault holds, as the engine would answer a read with. */
interface EngineState {
  contacts: number[];
  /** A scope mapped to `null` is one whose root the engine could not reach. */
  grants: Map<string, Array<[number, Permission]> | null>;
}

/**
 * The sharing surface the dialog drives, over engine-side state the accepted
 * commands mutate — so the dialog's re-read sees what a real engine would
 * report, and never what a command happened to return.
 */
function sharingEngine(refusals: Record<string, Error> = {}, held: Partial<EngineState> = {}) {
  const state: EngineState = {
    contacts: held.contacts ?? [],
    grants: held.grants ?? new Map(),
  };
  const answer = <T,>(name: string, value: T) =>
    refusals[name] === undefined ? Promise.resolve(value) : Promise.reject(refusals[name]);
  const rowsOf = (scope: Uint8Array) => state.grants.get(toHex(scope)) ?? [];
  const seedOf = (identityPublicKey: Uint8Array) => identityPublicKey[0] ?? 0;

  const facade = {
    subscribe: (_listener: (event: EventDescriptor) => void) => () => undefined,
    snapshot: () => new Promise<never>(() => undefined),
    setFocus: () => Promise.resolve(),
    sharing: vi.fn(
      (scope: Uint8Array): Promise<SharingDescriptor> =>
        answer('sharing', {
          scope,
          contacts: state.contacts.map((seed) => ({
            identityPublicKey: identity(seed),
          })),
          grants:
            state.grants.get(toHex(scope)) === null
              ? null
              : rowsOf(scope).map(([seed, permission]) => ({
                  recipientIdentityPublicKey: identity(seed),
                  permission,
                })),
        })
    ),
    importContact: vi.fn((code: Uint8Array) => {
      const seed = code[0] ?? 1;
      return answer('importContact', { kind: 'contactImported' as const }).then((outcome) => {
        if (!state.contacts.includes(seed)) state.contacts.push(seed);
        return outcome;
      });
    }),
    grant: vi.fn((scope: Uint8Array, recipient: Uint8Array, permission: Permission) =>
      answer('grant', { kind: 'done' as const }).then((outcome) => {
        state.grants.set(toHex(scope), [...rowsOf(scope), [seedOf(recipient), permission]]);
        return outcome;
      })
    ),
    revoke: vi.fn((scope: Uint8Array, recipient: Uint8Array) =>
      answer('revoke', { kind: 'done' as const }).then((outcome) => {
        state.grants.set(
          toHex(scope),
          rowsOf(scope).filter(([seed]) => seed !== seedOf(recipient))
        );
        return outcome;
      })
    ),
    createInviteLink: vi.fn((_scope: Uint8Array, _permission: Permission) =>
      answer('createInviteLink', { kind: 'inviteLinkMinted' as const, fragment: MINTED_FRAGMENT })
    ),
    downgrade: vi.fn((scope: Uint8Array, recipient: Uint8Array) =>
      answer('downgrade', { kind: 'done' as const }).then((outcome) => {
        state.grants.set(
          toHex(scope),
          rowsOf(scope).map(([seed, permission]): [number, Permission] =>
            seed === seedOf(recipient) ? [seed, 'read'] : [seed, permission]
          )
        );
        return outcome;
      })
    ),
  };

  const client = {
    facade,
    reportFocus: () => undefined,
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;

  return { client, facade };
}

/** Renders the dialog and lets its opening read land. */
async function share(engine = sharingEngine()) {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <EngineProvider createClient={() => engine.client}>{children}</EngineProvider>
  );
  await act(async () => {
    render(wrapper({ children: <ShareDialog row={folder} onClose={() => undefined} /> }));
  });
  return engine;
}

/** Clicks and lets the command it dispatched, and its re-read, settle. */
async function click(testId: string) {
  await act(async () => {
    fireEvent.click(screen.getByTestId(testId));
  });
}

/**
 * A vault whose engine already holds `contacts`, and `rows` on the folder —
 * `null` rows for a folder whose scope root the engine cannot reach.
 */
function held(contacts: number[], rows: Array<[number, Permission]> | null = []) {
  return { contacts, grants: new Map([[toHex(DOCS), rows]]) };
}

afterEach(() => sharingStore.clear());

describe('the grant list', () => {
  it('reports the emptiness of a scope the engine grants nothing on', async () => {
    await share();

    expect(screen.getByTestId('share-no-grants')).toBeTruthy();
    expect(screen.queryByTestId('share-grant-list')).toBeNull();
    // The list is engine truth now, so nothing on screen limits it to this
    // session's own commands.
    expect(screen.queryByTestId('share-session-note')).toBeNull();
  });

  it('does not draw a scope the engine could not reach as one granted to nobody', async () => {
    await share(sharingEngine({}, held([1], null)));

    expect(screen.getByTestId('share-grants-unavailable')).toBeTruthy();
    expect(screen.queryByTestId('share-no-grants')).toBeNull();
    expect(screen.queryByTestId('share-grant-list')).toBeNull();
  });

  it('lists a grant this session never issued, because the engine holds it', async () => {
    await share(sharingEngine({}, held([1], [[1, 'write']])));

    const rows = screen.getAllByTestId('share-grant-row');
    expect(rows).toHaveLength(1);
    expect(rows[0].textContent).toContain(key(1));
    expect(screen.getByTestId('share-grant-permission').textContent).toBe('write');
  });

  it('leaves no grant row once the engine accepted the revoke', async () => {
    const engine = await share(sharingEngine({}, held([1], [[1, 'read']])));

    await click('share-revoke');

    expect(engine.facade.revoke).toHaveBeenCalledWith(DOCS, identity(1));
    expect(screen.queryByTestId('share-grant-row')).toBeNull();
    expect(screen.getByTestId('share-no-grants')).toBeTruthy();
  });

  it('renders a downgrade as the row changing permission, not as a revoke', async () => {
    const engine = await share(sharingEngine({}, held([1], [[1, 'write']])));

    await click('share-downgrade');

    expect(engine.facade.downgrade).toHaveBeenCalledWith(DOCS, identity(1));
    expect(screen.getAllByTestId('share-grant-row')).toHaveLength(1);
    expect(screen.getByTestId('share-grant-permission').textContent).toBe('read');
    // Read is the floor a downgrade lands on, so the control is spent.
    expect(screen.queryByTestId('share-downgrade')).toBeNull();
  });

  it('keeps the write grant a refused downgrade left standing, and says why', async () => {
    await share(
      sharingEngine(
        { downgrade: new EngineRequestError('the publish was refused') },
        held([1], [[1, 'write']])
      )
    );

    await click('share-downgrade');

    expect(screen.getByTestId('share-grant-permission').textContent).toBe('write');
    expect(screen.getByTestId('dialog-error').textContent).toBe('the publish was refused');
  });
});

describe('granting', () => {
  it('grants the picked contact at the picked permission', async () => {
    const engine = await share(sharingEngine({}, held([1])));

    fireEvent.change(screen.getByLabelText('contact'), { target: { value: key(1) } });
    fireEvent.change(screen.getByLabelText('permission'), { target: { value: 'write' } });
    await click('share-grant');

    expect(engine.facade.grant).toHaveBeenCalledWith(DOCS, identity(1), 'write');
    expect(screen.getByTestId('share-grant-permission').textContent).toBe('write');
  });

  it('lists no row for a grant the engine refused', async () => {
    await share(
      sharingEngine({ grant: new EngineRequestError('the recipient is the owner') }, held([1]))
    );

    fireEvent.change(screen.getByLabelText('contact'), { target: { value: key(1) } });
    await click('share-grant');

    expect(screen.queryByTestId('share-grant-row')).toBeNull();
    expect(screen.getByTestId('dialog-error').textContent).toBe('the recipient is the owner');
  });

  it('cannot grant to a contact that already holds a grant here', async () => {
    await share(sharingEngine({}, held([1], [[1, 'read']])));

    expect(screen.getByTestId('share-no-contacts')).toBeTruthy();
    expect((screen.getByTestId('share-grant') as HTMLButtonElement).disabled).toBe(true);
  });
});

describe('the import step', () => {
  async function openImport(engine = sharingEngine()) {
    await share(engine);
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

describe('the invite link', () => {
  it('frames the engine fragment into the claim URL, in the URL fragment', async () => {
    const engine = await share();

    await click('share-mint-link');

    expect(engine.facade.createInviteLink).toHaveBeenCalledWith(DOCS, 'read');
    const url = new URL(screen.getByTestId<HTMLInputElement>('invite-link-url').value);
    expect(url.pathname).toBe('/invite');
    expect(url.hash).toBe(`#${MINTED_FRAGMENT}`);
    // A fragment reaches no server; a query string would.
    expect(url.search).toBe('');
    expect(screen.getByTestId('invite-link-bearer')).toBeTruthy();
  });

  it('copies the whole link, capability included', async () => {
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    await share();
    await click('share-mint-link');

    await click('invite-link-copy');

    expect(writeText).toHaveBeenCalledWith(
      screen.getByTestId<HTMLInputElement>('invite-link-url').value
    );
    expect(screen.getByTestId('invite-link-copy').textContent).toBe('copied');
  });

  it("renders the engine's refusal of a write link instead of a link", async () => {
    const refusal = new EngineRequestError('write-links-need-a-write-scope-cut', 'unsupported');
    await share(sharingEngine({ createInviteLink: refusal }));
    fireEvent.change(screen.getByLabelText('permission'), { target: { value: 'write' } });

    await click('share-mint-link');

    expect(screen.getByTestId('dialog-error').textContent).toBe(
      'write-links-need-a-write-scope-cut'
    );
    expect(screen.queryByTestId('invite-link-url')).toBeNull();
    expect(screen.getByTestId('share-mint-link')).toBeTruthy();
  });

  it('holds a shown link against a dismissal that would discard it', async () => {
    await share();

    await click('share-mint-link');

    expect(screen.getByLabelText('close').hasAttribute('disabled')).toBe(true);
  });
});
