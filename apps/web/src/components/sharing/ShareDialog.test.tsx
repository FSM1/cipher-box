import type { ReactNode } from 'react';
import { EngineRequestError, toHex } from '@cipherbox/client';
import type {
  EngineClient,
  EventDescriptor,
  Permission,
  SharingDescriptor,
  SharingInviteLinkDescriptor,
} from '@cipherbox/client';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { JOINED_NOTICE_MS } from '../../hooks/useSharingActions';
import { EngineProvider } from '../../providers/EngineProvider';
import { storedOwnerName, storeOwnerName } from '../../sharing/ownerName';
import { sharingStore } from '../../stores/sharing.store';
import type { ListingRow } from '../../vault/listing';
import { ShareDialog } from './ShareDialog';

const DOCS = new Uint8Array(16).fill(7);
/** This member's own contact code, as the engine hands it out. */
const OWN_CODE = new Uint8Array([0xc0, 0xde]);
const CODE_HEX = '00ff10';

/** Stands in for the engine's opaque capability; the UI reads none of it. */
const MINTED_FRAGMENT = 'a-minted-fragment';

/** The identity a converted claim lands in the ledger under. */
const CLAIMANT_SEED = 5;

const NO_LINKS: SharingInviteLinkDescriptor[] = [];

/** The tag of the link a seed names. */
function linkTag(seed: number): Uint8Array {
  return new Uint8Array(32).fill(seed);
}

/** A link as the engine reports it; its tag is what a revoke names. */
function inviteLink(seed: number, expiresAt: bigint): SharingInviteLinkDescriptor {
  return {
    tag: linkTag(seed),
    permission: 'read',
    expiresAt,
    expired: false,
    admissionCap: 5,
    pendingClaims: 0,
    contactBudgetFull: false,
    refusedClaims: 0,
  };
}

const folder: ListingRow = {
  id: DOCS,
  key: toHex(DOCS),
  name: 'docs',
  storedName: 'docs',
  kind: 'folder',
  icon: '[DIR]',
  size: '-',
  bytes: null,
  contentVersion: null,
  contentCid: null,
  modified: '-',
  pending: 'none',
  deadLetter: false,
  pendingInviteClaims: 0,
};

function identity(seed: number): Uint8Array {
  return new Uint8Array(33).fill(seed);
}

function key(seed: number): string {
  return toHex(identity(seed));
}

/** The fingerprint the engine forms for a seed's identity key. */
function fingerprint(seed: number): string {
  return `fp-${seed}`;
}

/** One ledger row: its grantee, its permission, and the seed of the link that admitted it. */
interface HeldGrant {
  seed: number;
  permission: Permission;
  viaLink?: number;
  name?: { name: string; source: 'owner' | 'claimant' };
}

/** The sharing state one vault holds, as the engine would answer a read with. */
interface EngineState {
  contacts: number[];
  /** A scope mapped to `null` is one whose root the engine could not reach. */
  grants: Map<string, HeldGrant[] | null>;
  links: SharingInviteLinkDescriptor[];
  /** The ground `share_scope` would refuse this target on, as the engine names it. */
  standing: ShareStanding;
}

/** The engine's `ShareChecks` rules, and the pair of names each carries. */
type ShareStanding = keyof typeof SHARE_STANDINGS;

const SHARE_STANDINGS = {
  accepted: { grant: null, inviteLink: null },
  vaultRoot: {
    grant: 'grant-target-is-the-vault-root',
    inviteLink: 'invite-target-is-the-vault-root',
  },
  envelopeVersion: {
    grant: 'grant-parent-envelope-version-unsupported',
    inviteLink: 'invite-parent-envelope-version-unsupported',
  },
} as const;

/**
 * The sharing surface the dialog drives, over engine-side state the accepted
 * commands mutate — so the dialog's re-read sees what a real engine would
 * report, and never what a command happened to return.
 */
function sharingEngine(refusals: Record<string, Error> = {}, held: Partial<EngineState> = {}) {
  const state: EngineState = {
    contacts: held.contacts ?? [],
    grants: held.grants ?? new Map(),
    links: held.links ?? NO_LINKS,
    standing: held.standing ?? 'accepted',
  };
  const answer = <T,>(name: string, value: T) =>
    refusals[name] === undefined ? Promise.resolve(value) : Promise.reject(refusals[name]);
  const rowsOf = (scope: Uint8Array) => state.grants.get(toHex(scope)) ?? [];
  const seedOf = (identityPublicKey: Uint8Array) => identityPublicKey[0] ?? 0;
  const edit = (scope: Uint8Array, recipient: Uint8Array, change: Partial<HeldGrant>) =>
    state.grants.set(
      toHex(scope),
      rowsOf(scope).map((row) => (row.seed === seedOf(recipient) ? { ...row, ...change } : row))
    );

  const listeners = new Set<(event: EventDescriptor) => void>();
  const facade = {
    subscribe: (listener: (event: EventDescriptor) => void) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    snapshot: () => new Promise<never>(() => undefined),
    setFocus: () => Promise.resolve(),
    sharing: vi.fn(
      (scope: Uint8Array): Promise<SharingDescriptor> =>
        answer('sharing', {
          scope,
          contacts: state.contacts.map((seed) => ({
            identityPublicKey: identity(seed),
            cachedName: null,
          })),
          ownContactCode: OWN_CODE,
          state:
            state.grants.get(toHex(scope)) === null
              ? null
              : {
                  grants: rowsOf(scope).map((row) => ({
                    recipientIdentityPublicKey: identity(row.seed),
                    permission: row.permission,
                    granteeName: row.name ?? null,
                    viaLink: row.viaLink === undefined ? null : linkTag(row.viaLink),
                  })),
                  grantRefusal: SHARE_STANDINGS[state.standing].grant,
                  inviteLinkRefusal: SHARE_STANDINGS[state.standing].inviteLink,
                  inviteLinks: state.links.map((link) => ({ ...link })),
                },
        })
    ),
    identityFingerprint: vi.fn((identityPublicKey: Uint8Array) =>
      Promise.resolve(fingerprint(seedOf(identityPublicKey)))
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
        state.grants.set(toHex(scope), [...rowsOf(scope), { seed: seedOf(recipient), permission }]);
        return outcome;
      })
    ),
    revoke: vi.fn((scope: Uint8Array, recipient: Uint8Array) =>
      answer('revoke', { kind: 'done' as const }).then((outcome) => {
        state.grants.set(
          toHex(scope),
          rowsOf(scope).filter((row) => row.seed !== seedOf(recipient))
        );
        return outcome;
      })
    ),
    createInviteLink: vi.fn(
      (_scope: Uint8Array, _permission: Permission, expiresAt?: bigint, _ownerName?: string) =>
        answer('createInviteLink', {
          kind: 'inviteLinkMinted' as const,
          fragment: MINTED_FRAGMENT,
        }).then((outcome) => {
          state.links = [...state.links, inviteLink(state.links.length + 1, expiresAt ?? 1n)];
          return outcome;
        })
    ),
    revokeInviteLink: vi.fn((_scope: Uint8Array, tag?: Uint8Array) =>
      answer('revokeInviteLink', { kind: 'done' as const }).then((outcome) => {
        state.links =
          tag === undefined ? [] : state.links.filter((link) => toHex(link.tag) !== toHex(tag));
        return outcome;
      })
    ),
    convertInviteClaims: vi.fn((scope: Uint8Array) =>
      answer('convertInviteClaims', { kind: 'done' as const }).then((outcome) => {
        const claimed = state.links.find((link) => link.pendingClaims > 0);
        if (claimed !== undefined) {
          state.grants.set(toHex(scope), [
            ...rowsOf(scope),
            { seed: CLAIMANT_SEED, permission: claimed.permission, viaLink: claimed.tag[0] },
          ]);
          state.links = state.links.map((link) =>
            link === claimed ? { ...link, pendingClaims: 0 } : link
          );
        }
        return outcome;
      })
    ),
    dismissRefusedClaims: vi.fn(() =>
      answer('dismissRefusedClaims', { kind: 'done' as const }).then((outcome) => {
        state.links = state.links.map((link) => ({ ...link, refusedClaims: 0 }));
        return outcome;
      })
    ),
    changePermission: vi.fn((scope: Uint8Array, recipient: Uint8Array, to: Permission) =>
      answer('changePermission', { kind: 'done' as const }).then((outcome) => {
        edit(scope, recipient, { permission: to });
        return outcome;
      })
    ),
    renameGrantee: vi.fn((scope: Uint8Array, recipient: Uint8Array, name: string) =>
      answer('renameGrantee', { kind: 'done' as const }).then((outcome) => {
        edit(scope, recipient, { name: { name, source: 'owner' } });
        return outcome;
      })
    ),
  };

  const client = {
    facade,
    reportFocus: () => undefined,
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;

  const emit = (event: EventDescriptor) => listeners.forEach((listener) => listener(event));
  return { client, facade, emit };
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
async function click(target: string | HTMLElement) {
  await act(async () => {
    fireEvent.click(typeof target === 'string' ? screen.getByTestId(target) : target);
  });
}

/** Changes a field and lets any command it dispatched settle. */
async function change(field: HTMLElement, value: string) {
  await act(async () => {
    fireEvent.change(field, { target: { value } });
  });
}

/**
 * A vault whose engine already holds `contacts`, and `rows` on the folder —
 * `null` rows for a folder whose scope root the engine cannot reach.
 */
function held(
  contacts: number[],
  rows: HeldGrant[] | null = [],
  rest: Partial<Pick<EngineState, 'links' | 'standing'>> = {}
) {
  return { contacts, grants: new Map([[toHex(DOCS), rows]]), ...rest };
}

afterEach(() => {
  sharingStore.clear();
  storeOwnerName('');
});

describe('the people table', () => {
  it('puts the owner first and says when no one else has access', async () => {
    await share();

    expect(screen.getByTestId('share-owner-row').textContent).toContain('you');
    expect(screen.getByTestId('share-no-grants')).toBeTruthy();
    expect(screen.queryByTestId('share-grant-row')).toBeNull();
  });

  it('counts the live links and says their holders can open the folder before any join', async () => {
    const live = { ...inviteLink(0x7a, 4_000_000_000_000n), pendingClaims: 2 };
    const expired = { ...inviteLink(0x7b, 1n), expired: true, pendingClaims: 4 };
    const running = new EngineRequestError('seam error: a-conversion-pass-is-running', 'seam');
    await share(
      sharingEngine({ convertInviteClaims: running }, held([], [], { links: [live, expired] }))
    );

    expect(screen.getByTestId('share-people-count').textContent).toBe(
      'people with access · 1 · 1 live link'
    );
    expect(screen.getByTestId('share-no-grants').textContent).toContain(
      'whoever holds a live link can already open this folder'
    );
    const waiting = screen.getAllByTestId('share-link-waiting');
    expect(waiting.map((line) => line.textContent)).toEqual([
      expect.stringMatching(/^\/\/ 2 claims waiting on the view link, expires/),
    ]);
  });

  it('does not draw a scope the engine could not reach as one shared with nobody', async () => {
    await share(sharingEngine({}, held([1], null)));

    expect(screen.getByText('people with access')).toBeTruthy();
    expect(screen.queryByText(/people with access ·/)).toBeNull();
    expect(screen.getByTestId('share-grants-unavailable')).toBeTruthy();
    expect(screen.queryByTestId('share-no-grants')).toBeNull();
    expect(screen.queryByTestId('share-people')).toBeNull();
  });

  it('lists a grant this session never issued, with its fingerprint on hover', async () => {
    await share(sharingEngine({}, held([1], [{ seed: 1, permission: 'write' }])));

    const rows = screen.getAllByTestId('share-grant-row');
    expect(rows).toHaveLength(1);
    const who = within(rows[0]).getByTestId('share-grantee');
    // No name on the row, so the fingerprint is what names it.
    expect(who.textContent).toBe(fingerprint(1));
    expect(who.getAttribute('title')).toBe(fingerprint(1));
    expect(within(rows[0]).getByTestId('share-got-in').textContent).toBe('direct');
    expect((screen.getByTestId('share-grant-permission') as HTMLSelectElement).value).toBe('write');
  });

  it('says who got in through a link, and marks a name the claimant chose', async () => {
    const joined: HeldGrant = {
      seed: 2,
      permission: 'read',
      viaLink: 0x7a,
      name: { name: 'Ada', source: 'claimant' },
    };
    await share(sharingEngine({}, held([], [joined])));

    expect(screen.getByTestId('share-got-in').textContent).toBe('via link');
    expect(screen.getByTestId('share-rename').textContent).toBe('Adasuggested');
  });

  it('revokes only after the confirmation, which shows the fingerprint', async () => {
    const engine = await share(sharingEngine({}, held([1], [{ seed: 1, permission: 'read' }])));

    await click('share-revoke');
    expect(engine.facade.revoke).not.toHaveBeenCalled();
    expect(screen.getByTestId('share-revoke-prompt').textContent).toContain(fingerprint(1));

    await click('share-revoke-confirm');

    expect(engine.facade.revoke).toHaveBeenCalledWith(DOCS, identity(1));
    expect(screen.queryByTestId('share-grant-row')).toBeNull();
    expect(screen.queryByTestId('share-revoke-prompt')).toBeNull();
  });

  it('names the confirmation by its title and describes it by its notes', async () => {
    await share(sharingEngine({}, held([1], [{ seed: 1, permission: 'read' }])));

    await click('share-revoke');

    const prompt = screen.getByRole('alertdialog', {
      name: `remove ${fingerprint(1)}?`,
      description: new RegExp(`fingerprint ${fingerprint(1)}`),
    });
    expect(prompt).toBe(screen.getByTestId('share-revoke-prompt'));
  });

  it('keeps the grant when the owner steps back from the confirmation', async () => {
    const engine = await share(sharingEngine({}, held([1], [{ seed: 1, permission: 'read' }])));

    await click('share-revoke');
    await click(screen.getByRole('button', { name: 'keep' }));

    expect(engine.facade.revoke).not.toHaveBeenCalled();
    expect(screen.getAllByTestId('share-grant-row')).toHaveLength(1);
  });

  it('changes a permission in place, to what the engine then commits', async () => {
    const engine = await share(sharingEngine({}, held([1], [{ seed: 1, permission: 'read' }])));

    await change(screen.getByTestId('share-grant-permission'), 'write');

    expect(engine.facade.changePermission).toHaveBeenCalledWith(DOCS, identity(1), 'write');
    expect((screen.getByTestId('share-grant-permission') as HTMLSelectElement).value).toBe('write');
  });

  it('keeps the permission a refused change left standing, and says why', async () => {
    await share(
      sharingEngine(
        { changePermission: new EngineRequestError('unsupported target: grant-row-is-a-link') },
        held([1], [{ seed: 1, permission: 'write' }])
      )
    );

    await change(screen.getByTestId('share-grant-permission'), 'read');

    expect((screen.getByTestId('share-grant-permission') as HTMLSelectElement).value).toBe('write');
    expect(screen.getByTestId('dialog-error').textContent).toContain('mint a new one');
  });

  it('renames a grantee inline and shows the name the engine committed', async () => {
    const engine = await share(sharingEngine({}, held([1], [{ seed: 1, permission: 'read' }])));

    await click('share-rename');
    fireEvent.change(screen.getByTestId('share-rename-input'), { target: { value: '  Ada ' } });
    await click('share-rename-save');

    expect(engine.facade.renameGrantee).toHaveBeenCalledWith(DOCS, identity(1), 'Ada');
    expect(screen.queryByTestId('share-rename-input')).toBeNull();
    expect(screen.getByTestId('share-rename').textContent).toBe('Ada');
  });

  it('sends no empty name', async () => {
    const engine = await share(sharingEngine({}, held([1], [{ seed: 1, permission: 'read' }])));

    await click('share-rename');
    fireEvent.change(screen.getByTestId('share-rename-input'), { target: { value: '   ' } });

    expect((screen.getByTestId('share-rename-save') as HTMLButtonElement).disabled).toBe(true);
    expect(engine.facade.renameGrantee).not.toHaveBeenCalled();
  });
});

describe('the contact-code path', () => {
  it('sits under advanced, collapsed', async () => {
    await share();

    expect((screen.getByTestId('share-advanced') as HTMLDetailsElement).open).toBe(false);
  });

  it('grants the picked contact at the picked permission', async () => {
    const engine = await share(sharingEngine({}, held([1])));

    fireEvent.change(screen.getByLabelText('contact'), { target: { value: key(1) } });
    fireEvent.change(screen.getByLabelText('contact permission'), {
      target: { value: 'write' },
    });
    await click('share-grant');

    expect(engine.facade.grant).toHaveBeenCalledWith(DOCS, identity(1), 'write');
    expect((screen.getByTestId('share-grant-permission') as HTMLSelectElement).value).toBe('write');
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
    await share(sharingEngine({}, held([1], [{ seed: 1, permission: 'read' }])));

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

    fireEvent.change(screen.getByLabelText('their contact code'), { target: { value: CODE_HEX } });
    await click('import-contact-confirm');

    expect(engine.facade.importContact).toHaveBeenCalledWith(new Uint8Array([0x00, 0xff, 0x10]));
    await waitFor(() => expect(screen.getByTestId('share-dialog')).toBeTruthy());
    expect(screen.getByLabelText('contact')).toBeTruthy();
  });

  it('refuses to send a paste that is not a code, without calling it unverified', async () => {
    const engine = await openImport();

    fireEvent.change(screen.getByLabelText('their contact code'), {
      target: { value: 'not a code' },
    });

    expect(screen.getByTestId('import-contact-unreadable')).toBeTruthy();
    expect((screen.getByTestId('import-contact-confirm') as HTMLButtonElement).disabled).toBe(true);
    expect(engine.facade.importContact).not.toHaveBeenCalled();
  });

  it("shows the engine's refusal for a code whose binding did not verify", async () => {
    const refusal = new EngineRequestError('contact-code-binding refused', 'trustViolation');
    await openImport(sharingEngine({ importContact: refusal }));

    fireEvent.change(screen.getByLabelText('their contact code'), { target: { value: CODE_HEX } });
    await click('import-contact-confirm');

    expect(screen.getByTestId('dialog-error').textContent).toBe('contact-code-binding refused');
    expect(screen.getByTestId('import-contact-form')).toBeTruthy();
    expect(sharingStore.getState().contacts).toEqual([]);
  });

  it("shows this member's own code so the exchange can go both ways", async () => {
    await openImport();

    // Hex, the encoding the paste field beside it parses, so two members can
    // exchange with only what the dialog shows them.
    expect(screen.getByTestId('own-contact-code').textContent).toContain(toHex(OWN_CODE));
    expect(screen.getByLabelText('copy your contact code')).toBeTruthy();
  });

  it('retires the import refusal when the step it belongs to is left', async () => {
    const refusal = new EngineRequestError('contact-code-binding refused', 'trustViolation');
    await openImport(sharingEngine({ importContact: refusal }));
    fireEvent.change(screen.getByLabelText('their contact code'), { target: { value: CODE_HEX } });
    await click('import-contact-confirm');

    await click('import-contact-cancel');

    expect(screen.getByTestId('share-dialog')).toBeTruthy();
    expect(screen.queryByTestId('dialog-error')).toBeNull();
  });
});

/** The link the dialog is showing, as the member reads it. */
function shownLink(): string {
  return (
    screen.getByTestId('invite-link').querySelector('.details-copyable-text')?.textContent ?? ''
  );
}

/** Noon on a fixed day, so a minted deadline is an exact number. */
const MINTED_AT = Date.UTC(2026, 7, 25, 12);
const SEVEN_DAYS_ON = BigInt(MINTED_AT + 7 * 86_400_000);

describe('creating a link', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(MINTED_AT);
  });
  afterEach(() => vi.useRealTimers());

  it('mints under the permission, the lifetime and the name the owner picks', async () => {
    const engine = await share();

    fireEvent.change(screen.getByLabelText('link permission'), { target: { value: 'write' } });
    fireEvent.change(screen.getByLabelText('link expires'), { target: { value: '30 days' } });
    fireEvent.change(screen.getByLabelText('your name on the link'), {
      target: { value: ' Mia ' },
    });
    await click('share-mint-link');

    expect(engine.facade.createInviteLink).toHaveBeenCalledWith(
      DOCS,
      'write',
      BigInt(MINTED_AT + 30 * 86_400_000),
      'Mia',
      25
    );
  });

  it('mints under the admission cap the owner sets', async () => {
    const engine = await share();

    fireEvent.change(screen.getByLabelText('link admits up to'), { target: { value: '3' } });
    await click('share-mint-link');

    expect(engine.facade.createInviteLink).toHaveBeenCalledWith(DOCS, 'read', SEVEN_DAYS_ON, '', 3);
  });

  it('offers no mint while the cap field holds no whole number', async () => {
    const engine = await share();

    for (const value of ['', '2.5']) {
      fireEvent.change(screen.getByLabelText('link admits up to'), { target: { value } });
      expect(screen.getByTestId('share-mint-link').hasAttribute('disabled')).toBe(true);
    }
    await click('share-mint-link');

    expect(engine.facade.createInviteLink).not.toHaveBeenCalled();
  });

  it("says the engine's refusal of a cap out of its range in words", async () => {
    const refusal = new EngineRequestError(
      'malformed input: invite-admission-cap-out-of-range',
      'malformedInput'
    );
    await share(sharingEngine({ createInviteLink: refusal }));

    fireEvent.change(screen.getByLabelText('link admits up to'), { target: { value: '0' } });
    await click('share-mint-link');

    expect(screen.getByTestId('dialog-error').textContent).toContain('a link admits from 1 to');
  });

  it('keeps the owner name for the next mint, and mints with none when it is empty', async () => {
    storeOwnerName('Mia');
    const engine = await share();

    expect((screen.getByLabelText('your name on the link') as HTMLInputElement).value).toBe('Mia');
    fireEvent.change(screen.getByLabelText('your name on the link'), { target: { value: '' } });
    await click('share-mint-link');

    expect(engine.facade.createInviteLink).toHaveBeenCalledWith(
      DOCS,
      'read',
      SEVEN_DAYS_ON,
      '',
      25
    );
    expect(storedOwnerName()).toBe('');
  });

  it('keeps the name in this tab only, and only once a mint lands', async () => {
    const refusal = new EngineRequestError('malformed input: invite-name-too-long');
    await share(sharingEngine({ createInviteLink: refusal }));

    fireEvent.change(screen.getByLabelText('your name on the link'), {
      target: { value: 'Mia' },
    });
    await click('share-mint-link');
    expect(storedOwnerName()).toBe('');

    cleanup();
    await share();
    fireEvent.change(screen.getByLabelText('your name on the link'), {
      target: { value: 'Mia' },
    });
    await click('share-mint-link');

    expect(sessionStorage.getItem('cipherbox.share.ownerName')).toBe('Mia');
    expect(localStorage.getItem('cipherbox.share.ownerName')).toBeNull();
  });

  it('flags a write link as one that makes every holder a writer', async () => {
    await share();

    expect(screen.queryByTestId('share-write-link-flag')).toBeNull();
    fireEvent.change(screen.getByLabelText('link permission'), { target: { value: 'write' } });

    expect(screen.getByTestId('share-write-link-flag').textContent).toContain(
      'each URL holder becomes a writer after conversion, with no owner step'
    );
  });

  it('frames the engine fragment into the claim URL, in the URL fragment', async () => {
    await share();

    await click('share-mint-link');

    const url = new URL(shownLink());
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

    await act(async () => {
      fireEvent.click(screen.getByLabelText('copy invite link'));
    });

    expect(writeText).toHaveBeenCalledWith(shownLink());
  });

  it("renders the engine's refusal of a mint instead of a link", async () => {
    const refusal = new EngineRequestError(
      'unsupported target: invite-target-index-lost-a-root',
      'unsupportedTarget'
    );
    await share(sharingEngine({ createInviteLink: refusal }));

    await click('share-mint-link');

    expect(screen.getByTestId('dialog-error').textContent).toContain('no link can be minted here');
    expect(screen.queryByTestId('invite-link')).toBeNull();
    expect(screen.getByTestId('share-mint-link')).toBeTruthy();
  });

  it('mints one link however fast the control is activated twice', async () => {
    const engine = await share();

    // Both land before React commits the busy state, so a second link would be
    // a live capability the member never sees and cannot revoke.
    await act(async () => {
      const mint = screen.getByTestId('share-mint-link');
      mint.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      mint.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });

    expect(engine.facade.createInviteLink).toHaveBeenCalledTimes(1);
  });

  it('offers no second mint while a link is shown, so the shown link stays the live one', async () => {
    await share();

    await click('share-mint-link');

    expect(shownLink()).toContain(MINTED_FRAGMENT);
    expect(screen.getByTestId('share-mint-link').hasAttribute('disabled')).toBe(true);
  });

  it('holds a shown link against a dismissal that would discard it', async () => {
    await share();

    await click('share-mint-link');

    expect(screen.getByLabelText('close').hasAttribute('disabled')).toBe(true);
  });
});

describe('the links a scope carries', () => {
  const LIVE = inviteLink(0x7a, 4_000_000_000_000n);

  it('draws one chip per link, a link this session never minted included', async () => {
    const second = { ...inviteLink(0x7b, 4_000_000_000_000n), permission: 'write' as const };
    await share(sharingEngine({}, held([], [], { links: [LIVE, second] })));

    const chips = screen.getAllByTestId('share-link-chip');
    expect(chips.map((chip) => chip.textContent)).toEqual([
      expect.stringContaining('view · expires'),
      expect.stringContaining('edit · expires'),
    ]);
    // The capability was handed over once, at the mint; nothing can re-derive it.
    expect(screen.queryByTestId('invite-link')).toBeNull();
    // A scope takes many links, so a live one leaves the mint on offer.
    expect(screen.getByTestId('share-mint-link')).toBeTruthy();
  });

  it('shows what waits on a link and a link whose contact share is full', async () => {
    const full = new EngineRequestError(
      'unsupported target: invite-link-contact-budget-full',
      'unsupportedTarget'
    );
    await share(
      sharingEngine(
        { convertInviteClaims: full },
        held([], [], { links: [{ ...LIVE, pendingClaims: 2, contactBudgetFull: true }] })
      )
    );

    expect(screen.getByTestId('share-pending-claims').textContent).toBe('· 2 claims waiting');
    expect(screen.getByTestId('share-link-full')).toBeTruthy();
    expect(screen.getByTestId('dialog-error').textContent).toContain('revoke a link');
  });

  it('marks no full link where the engine counts room', async () => {
    await share(sharingEngine({}, held([], [], { links: [LIVE] })));

    expect(screen.queryByTestId('share-link-full')).toBeNull();
    expect(screen.queryByTestId('share-pending-claims')).toBeNull();
  });

  it('converts the claims waiting on a link when the dialog opens', async () => {
    const waiting = { ...LIVE, pendingClaims: 1 };
    const engine = await share(sharingEngine({}, held([], [], { links: [waiting] })));

    expect(engine.facade.convertInviteClaims).toHaveBeenCalledWith(DOCS);
    const rows = screen.getAllByTestId('share-grant-row');
    expect(rows).toHaveLength(1);
    expect(within(rows[0]).getByTestId('share-got-in').textContent).toBe('via link');
    expect(screen.queryByText('convert claims')).toBeNull();
  });

  it('converts nothing on open where the folder carries no link', async () => {
    const engine = await share();

    expect(engine.facade.convertInviteClaims).not.toHaveBeenCalled();
  });

  it('cuts the link its chip names, after a confirmation that names it', async () => {
    const other = inviteLink(0x7b, 4_000_000_000_000n);
    const engine = await share(sharingEngine({}, held([], [], { links: [LIVE, other] })));

    await click(screen.getAllByTestId('share-revoke-link')[1]);
    expect(engine.facade.revokeInviteLink).not.toHaveBeenCalled();
    expect(screen.getByTestId('share-link-revoke-prompt').textContent).toContain('view link');
    expect(screen.queryByTestId('share-link-keepers')).toBeNull();
    expect(screen.queryByTestId('share-link-unclear')).toBeNull();

    await click('share-link-revoke-confirm');

    expect(engine.facade.revokeInviteLink).toHaveBeenCalledWith(DOCS, other.tag, false);
    expect(screen.getAllByTestId('share-link-chip')).toHaveLength(1);
    expect(screen.queryByTestId('share-link-revoke-prompt')).toBeNull();
  });

  it('names the people who joined through a link and keep access past its revoke', async () => {
    const rows: HeldGrant[] = [
      { seed: 2, permission: 'read', viaLink: 0x7a, name: { name: 'Ada', source: 'owner' } },
      { seed: 3, permission: 'read', name: { name: 'Bo', source: 'owner' } },
    ];
    await share(sharingEngine({}, held([], rows, { links: [LIVE] })));

    await click('share-revoke-link');

    const keepers = screen.getByTestId('share-link-keepers');
    expect(keepers.textContent).toBe(`// these keep access: Ada (${fingerprint(2)})`);
    expect(screen.queryByTestId('share-link-unclear')).toBeNull();
    const remove = screen.getByTestId('share-link-remove-grantees');
    expect(remove.parentElement?.textContent).toBe(
      'also remove the 1 person who joined through it'
    );

    await click(remove);
    expect(keepers.textContent).toContain('these lose access');
  });

  it('drops the remove choice when the owner turns to another link', async () => {
    const other = inviteLink(0x7b, 4_000_000_000_000n);
    const rows: HeldGrant[] = [{ seed: 2, permission: 'read', viaLink: 0x7a }];
    const engine = await share(sharingEngine({}, held([], rows, { links: [LIVE, other] })));

    await click(screen.getAllByTestId('share-revoke-link')[0]);
    await click('share-link-remove-grantees');
    await click(screen.getAllByTestId('share-revoke-link')[1]);
    expect(screen.getByTestId<HTMLInputElement>('share-link-remove-grantees').checked).toBe(false);

    await click('share-link-revoke-confirm');

    expect(engine.facade.revokeInviteLink).toHaveBeenCalledWith(DOCS, other.tag, false);
    expect(screen.queryByTestId('dialog-error')).toBeNull();
    expect(screen.getAllByTestId('share-link-chip')).toHaveLength(1);
  });

  it.each([
    ['checked', true],
    ['unchecked', false],
  ])('sends the remove choice to the engine with the box %s', async (_state, removeGrantees) => {
    const rows: HeldGrant[] = [{ seed: 2, permission: 'read', viaLink: 0x7a }];
    const engine = await share(sharingEngine({}, held([], rows, { links: [LIVE] })));

    await click('share-revoke-link');
    if (removeGrantees) await click('share-link-remove-grantees');
    await click('share-link-revoke-confirm');

    expect(engine.facade.revokeInviteLink).toHaveBeenCalledWith(DOCS, LIVE.tag, removeGrantees);
    expect(screen.queryByTestId('dialog-error')).toBeNull();
    expect(screen.queryByTestId('share-link-chip')).toBeNull();
    expect(screen.queryByTestId('share-link-revoke-prompt')).toBeNull();
  });

  // The engine shows no link and no name on a row the owner does not attest,
  // and a revoke with remove-grantees can still take that row.
  it('offers the remove choice and marks the list unclear past a grant it cannot place', async () => {
    const rows: HeldGrant[] = [
      { seed: 2, permission: 'read', viaLink: 0x7a, name: { name: 'Ada', source: 'owner' } },
      { seed: 3, permission: 'read' },
    ];
    const engine = await share(sharingEngine({}, held([], rows, { links: [LIVE] })));

    await click('share-revoke-link');

    expect(screen.getByTestId('share-link-keepers').textContent).toBe(
      `// these keep access: Ada (${fingerprint(2)})`
    );
    expect(screen.getByTestId('share-link-unclear').textContent).toBe(
      '// 1 grant with no name and no link may have joined through it'
    );
    const remove = screen.getByTestId('share-link-remove-grantees');
    expect(remove.parentElement?.textContent).toBe('also remove the people who joined through it');

    await click(remove);
    await click('share-link-revoke-confirm');

    expect(engine.facade.revokeInviteLink).toHaveBeenCalledWith(DOCS, LIVE.tag, true);
  });

  it('sends the remove choice when no grant names the link', async () => {
    const rows: HeldGrant[] = [{ seed: 3, permission: 'read' }];
    const engine = await share(sharingEngine({}, held([], rows, { links: [LIVE] })));

    await click('share-revoke-link');

    expect(screen.queryByTestId('share-link-keepers')).toBeNull();
    expect(screen.getByTestId('share-link-unclear')).toBeTruthy();
    await click('share-link-remove-grantees');
    await click('share-link-revoke-confirm');

    expect(engine.facade.revokeInviteLink).toHaveBeenCalledWith(DOCS, LIVE.tag, true);
  });

  it('draws no link section at all for a scope root the engine could not reach', async () => {
    await share(sharingEngine({}, held([], null)));

    expect(screen.getByTestId('share-grants-unavailable')).toBeTruthy();
    expect(screen.queryByTestId('share-links')).toBeNull();
    expect(screen.queryByTestId('share-mint-link')).toBeNull();
  });

  it('shows no refusal on open while another conversion pass runs', async () => {
    const running = new EngineRequestError('seam error: a-conversion-pass-is-running', 'seam');
    await share(
      sharingEngine(
        { convertInviteClaims: running },
        held([], [], { links: [{ ...LIVE, pendingClaims: 1 }] })
      )
    );

    expect(screen.queryByTestId('dialog-error')).toBeNull();
    expect(screen.getAllByTestId('share-link-chip')).toHaveLength(1);
  });

  it.each([['the-conversion-record-is-full', 'holds all the claims it can']])(
    'says in words that the open-time conversion refused on %s, and still offers the dialog',
    async (check, words) => {
      const refusal = new EngineRequestError(`seam error: ${check}`, 'seam');
      await share(
        sharingEngine(
          { convertInviteClaims: refusal },
          held([], [], { links: [{ ...LIVE, pendingClaims: 1 }] })
        )
      );

      expect(screen.getByTestId('dialog-error').textContent).toContain(words);
      expect(screen.getAllByTestId('share-link-chip')).toHaveLength(1);
      expect(screen.getByTestId('share-mint-link').hasAttribute('disabled')).toBe(false);
    }
  );

  it('counts the claims a link refused at a cap, and dismisses them for the folder', async () => {
    const engine = await share(
      sharingEngine({}, held([], [], { links: [{ ...LIVE, refusedClaims: 3 }] }))
    );

    expect(screen.getByTestId('share-refused-claims').textContent).toBe('· 3 claims refused');
    await click('share-dismiss-refused');

    expect(engine.facade.dismissRefusedClaims).toHaveBeenCalledWith(DOCS);
    expect(screen.queryByTestId('share-refused-claims')).toBeNull();
    expect(screen.queryByTestId('share-dismiss-refused')).toBeNull();
  });

  it('offers no dismiss where no link refused a claim', async () => {
    await share(sharingEngine({}, held([], [], { links: [LIVE] })));

    expect(screen.queryByTestId('share-refused-claims')).toBeNull();
    expect(screen.queryByTestId('share-dismiss-refused')).toBeNull();
  });
});

describe('the joined notice', () => {
  const FINGERPRINT = 'abcd ef01 2345 6789 abcd';
  const joined = (scopeRoot: Uint8Array, name: string): EventDescriptor => ({
    kind: 'granteeJoined',
    scopeRoot,
    name,
    fingerprint: FINGERPRINT,
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('names the joiner with the fingerprint prefix beside the name they chose', async () => {
    const engine = await share();

    await act(async () => engine.emit(joined(DOCS, 'Ada')));

    expect(screen.getByTestId('share-joined').textContent).toBe(
      '// Ada (abcd ef01) joined through a link'
    );
  });

  it('names a joiner who chose no name by the fingerprint prefix alone', async () => {
    const engine = await share();

    await act(async () => engine.emit(joined(DOCS, '')));

    expect(screen.getByTestId('share-joined').textContent).toBe(
      '// abcd ef01 joined through a link'
    );
  });

  it('re-reads the folder so the joiner shows in the table', async () => {
    const engine = await share();
    const reads = engine.facade.sharing.mock.calls.length;

    await act(async () => engine.emit(joined(DOCS, 'Ada')));

    expect(engine.facade.sharing.mock.calls.length).toBe(reads + 1);
  });

  it('says nothing for a join on another folder', async () => {
    const engine = await share();

    await act(async () => engine.emit(joined(new Uint8Array(16).fill(9), 'Ada')));

    expect(screen.queryByTestId('share-joined')).toBeNull();
  });

  it('lapses on its own', async () => {
    const engine = await share();
    vi.useFakeTimers();

    await act(async () => engine.emit(joined(DOCS, 'Ada')));
    expect(screen.getByTestId('share-joined')).toBeTruthy();
    await act(async () => {
      vi.advanceTimersByTime(JOINED_NOTICE_MS);
    });

    expect(screen.queryByTestId('share-joined')).toBeNull();
  });
});

/**
 * The engine refuses a share on two grounds, each under its own name per
 * command (`ShareChecks`). What the dialog offers has to follow both, and
 * offer nothing the engine would refuse on the target's standing.
 */
describe('what the dialog offers for each ground the engine refuses on', () => {
  const REFUSING: ShareStanding[] = ['vaultRoot', 'envelopeVersion'];

  it('offers both a grant and a mint where the engine accepts both', async () => {
    await share(sharingEngine({}, held([1], [], { standing: 'accepted' })));

    fireEvent.change(screen.getByLabelText('contact'), { target: { value: key(1) } });

    expect(screen.getByTestId('share-mint-link')).toBeTruthy();
    expect(screen.getByTestId('share-grant').hasAttribute('disabled')).toBe(false);
    expect(screen.queryByTestId('share-no-grant')).toBeNull();
    expect(screen.queryByTestId('share-no-mint')).toBeNull();
  });

  it.each(REFUSING)('dispatches neither where the engine refuses on %s', async (standing) => {
    const engine = await share(sharingEngine({}, held([1], [], { standing })));

    expect(screen.queryByLabelText('contact')).toBeNull();
    expect(screen.queryByTestId('share-mint-link')).toBeNull();
    expect(screen.getByTestId('share-grant').hasAttribute('disabled')).toBe(true);

    await click('share-grant');
    expect(engine.facade.grant).not.toHaveBeenCalled();
    expect(engine.facade.createInviteLink).not.toHaveBeenCalled();
  });

  it.each(REFUSING)('names the engine’s own ground for %s, per command', async (standing) => {
    await share(sharingEngine({}, held([1], [], { standing })));

    expect(screen.getByTestId('share-no-grant').getAttribute('data-check')).toBe(
      SHARE_STANDINGS[standing].grant
    );
    expect(screen.getByTestId('share-no-mint').getAttribute('data-check')).toBe(
      SHARE_STANDINGS[standing].inviteLink
    );
  });

  it('offers no grant where no read reached the scope, and says so in its own words', async () => {
    const engine = await share(sharingEngine({}, held([1], null)));

    // Absence is its own state: neither an offer, nor a refusal the engine made.
    expect(screen.getByTestId('share-standing-unknown')).toBeTruthy();
    expect(screen.queryByTestId('share-no-grant')).toBeNull();
    expect(screen.queryByLabelText('contact')).toBeNull();
    expect(screen.getByTestId('share-grant').hasAttribute('disabled')).toBe(true);

    await click('share-grant');
    expect(engine.facade.grant).not.toHaveBeenCalled();
  });
});
