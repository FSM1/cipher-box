import type { ReactNode } from 'react';
import { EngineRequestError, toHex } from '@cipherbox/client';
import type {
  EngineClient,
  EventDescriptor,
  Permission,
  SharingDescriptor,
  SharingInviteLinksDescriptor,
} from '@cipherbox/client';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EngineProvider } from '../../providers/EngineProvider';
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

const NO_LINKS: SharingInviteLinksDescriptor = {
  live: false,
  expired: false,
  expiresAt: null,
  spent: 0,
};

const folder: ListingRow = {
  id: DOCS,
  key: toHex(DOCS),
  name: 'docs',
  kind: 'folder',
  icon: '[DIR]',
  size: '-',
  bytes: null,
  contentVersion: null,
  contentCid: null,
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
  /** `null` for an owner whose link records the engine could not open. */
  links: SharingInviteLinksDescriptor | null;
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
  alreadyAScope: {
    grant: 'grant-target-already-names-a-scope',
    inviteLink: 'invite-target-already-names-a-scope',
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
    links: held.links === undefined ? NO_LINKS : held.links,
    standing: held.standing ?? 'accepted',
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
          ownContactCode: OWN_CODE,
          state:
            state.grants.get(toHex(scope)) === null
              ? null
              : {
                  grants: rowsOf(scope).map(([seed, permission]) => ({
                    recipientIdentityPublicKey: identity(seed),
                    permission,
                  })),
                  grantRefusal: SHARE_STANDINGS[state.standing].grant,
                  inviteLinkRefusal: SHARE_STANDINGS[state.standing].inviteLink,
                  inviteLinks: state.links === null ? null : { ...state.links },
                },
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
    createInviteLink: vi.fn((_scope: Uint8Array, _permission: Permission, expiresAt?: bigint) =>
      answer('createInviteLink', {
        kind: 'inviteLinkMinted' as const,
        fragment: MINTED_FRAGMENT,
      }).then((outcome) => {
        state.links = { ...(state.links ?? NO_LINKS), live: true, expiresAt: expiresAt ?? null };
        state.standing = 'alreadyAScope';
        return outcome;
      })
    ),
    revokeInviteLink: vi.fn(() =>
      answer('revokeInviteLink', { kind: 'done' as const }).then((outcome) => {
        state.links = {
          ...(state.links ?? NO_LINKS),
          live: false,
          expired: false,
          expiresAt: null,
        };
        return outcome;
      })
    ),
    pruneInviteLinks: vi.fn(() =>
      answer('pruneInviteLinks', { kind: 'done' as const }).then((outcome) => {
        state.links = { ...(state.links ?? NO_LINKS), spent: 0 };
        return outcome;
      })
    ),
    convertInviteClaims: vi.fn((scope: Uint8Array) =>
      answer('convertInviteClaims', { kind: 'done' as const }).then((outcome) => {
        state.grants.set(toHex(scope), [...rowsOf(scope), [CLAIMANT_SEED, 'read']]);
        return outcome;
      })
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
function held(
  contacts: number[],
  rows: Array<[number, Permission]> | null = [],
  rest: Partial<Pick<EngineState, 'links' | 'standing'>> = {}
) {
  return { contacts, grants: new Map([[toHex(DOCS), rows]]), ...rest };
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

describe('the invite link', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(MINTED_AT);
  });
  afterEach(() => vi.useRealTimers());

  it('mints a link that expires, unless the owner asks for one that does not', async () => {
    const engine = await share();

    fireEvent.change(screen.getByLabelText('link expires'), { target: { value: 'never' } });
    await click('share-mint-link');

    // `undefined` is the engine's "no deadline"; the default above is not it.
    expect(engine.facade.createInviteLink).toHaveBeenCalledWith(DOCS, 'read', undefined);
  });

  it('frames the engine fragment into the claim URL, in the URL fragment', async () => {
    const engine = await share();

    await click('share-mint-link');

    expect(engine.facade.createInviteLink).toHaveBeenCalledWith(DOCS, 'read', SEVEN_DAYS_ON);
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
    const refusal = new EngineRequestError('invite-target-already-names-a-scope', 'unsupported');
    await share(sharingEngine({ createInviteLink: refusal }));
    fireEvent.change(screen.getByLabelText('permission'), { target: { value: 'write' } });

    await click('share-mint-link');

    expect(screen.getByTestId('dialog-error').textContent).toBe(
      'invite-target-already-names-a-scope'
    );
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

  it('holds a shown link against a dismissal that would discard it', async () => {
    await share();

    await click('share-mint-link');

    expect(screen.getByLabelText('close').hasAttribute('disabled')).toBe(true);
  });
});

describe('a link the engine already holds', () => {
  const live: SharingInviteLinksDescriptor = {
    ...NO_LINKS,
    live: true,
    expiresAt: SEVEN_DAYS_ON,
  };

  it('draws the standing of a link this session never minted', async () => {
    await share(sharingEngine({}, held([], [], { links: live, standing: 'alreadyAScope' })));

    expect(screen.getByTestId('share-live-link')).toBeTruthy();
    expect(screen.getByTestId('share-live-link-expiry').textContent).toContain('expires');
    // The capability was handed over once, at the mint; nothing can re-derive it.
    expect(screen.queryByTestId('invite-link')).toBeNull();
  });

  it('offers no mint where the engine would refuse one', async () => {
    await share(sharingEngine({}, held([], [], { links: live, standing: 'alreadyAScope' })));

    expect(screen.queryByTestId('share-mint-link')).toBeNull();
  });

  it('says so rather than offering a mint on a shared folder carrying no link', async () => {
    await share(sharingEngine({}, held([1], [[1, 'read']], { standing: 'alreadyAScope' })));

    expect(screen.getByTestId('share-no-mint')).toBeTruthy();
    expect(screen.queryByTestId('share-mint-link')).toBeNull();
  });

  it('ends the link on a revoke and leaves the grants it converted standing', async () => {
    const engine = await share(
      sharingEngine(
        {},
        held([], [[CLAIMANT_SEED, 'read']], { links: live, standing: 'alreadyAScope' })
      )
    );

    await click('share-revoke-link');

    expect(engine.facade.revokeInviteLink).toHaveBeenCalledWith(DOCS);
    expect(screen.queryByTestId('share-live-link')).toBeNull();
    expect(screen.getAllByTestId('share-grant-row')).toHaveLength(1);
  });

  it('shows the grant a conversion committed', async () => {
    const engine = await share(
      sharingEngine({}, held([], [], { links: live, standing: 'alreadyAScope' }))
    );

    await click('share-convert-claims');

    expect(engine.facade.convertInviteClaims).toHaveBeenCalledWith(DOCS);
    expect(screen.getAllByTestId('share-grant-row')).toHaveLength(1);
  });

  it('offers to forget the records a cut left behind, and stops once pruned', async () => {
    const engine = await share(
      sharingEngine({}, held([], [], { links: { ...live, spent: 2 }, standing: 'alreadyAScope' }))
    );

    expect(screen.getByTestId('share-prune-links').textContent).toContain('2 spent link records');
    await click('share-prune-links');

    expect(engine.facade.pruneInviteLinks).toHaveBeenCalledWith(DOCS);
    expect(screen.queryByTestId('share-prune-links')).toBeNull();
  });

  it('says the standing is unknown when the owner’s link records would not open', async () => {
    await share(sharingEngine({}, held([], [], { links: null })));

    expect(screen.getByTestId('share-links-unavailable')).toBeTruthy();
    expect(screen.queryByTestId('share-mint-link')).toBeNull();
  });

  it('draws no link section at all for a scope root the engine could not reach', async () => {
    await share(sharingEngine({}, held([], null)));

    expect(screen.getByTestId('share-grants-unavailable')).toBeTruthy();
    expect(screen.queryByTestId('share-links-unavailable')).toBeNull();
    expect(screen.queryByTestId('share-mint-link')).toBeNull();
  });
});

/**
 * The engine refuses a share on three grounds, each under its own name per
 * command (`ShareChecks`). What the dialog offers has to follow all three, and
 * offer nothing the engine would refuse on the target's standing.
 */
describe('what the dialog offers for each ground the engine refuses on', () => {
  const REFUSING: ShareStanding[] = ['vaultRoot', 'alreadyAScope', 'envelopeVersion'];

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
