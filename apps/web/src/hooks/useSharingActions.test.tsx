import type { ReactNode } from 'react';
import { EngineRequestError, toHex } from '@cipherbox/client';
import type {
  EngineClient,
  EventDescriptor,
  Permission,
  SharingDescriptor,
  SharingInviteLinksDescriptor,
} from '@cipherbox/client';
import { renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EngineProvider } from '../providers/EngineProvider';
import { sharingFor, sharingStore, type GrantRow } from '../stores/sharing.store';
import { useSharingActions, type SharingCommand } from './useSharingActions';

const DOCS = new Uint8Array(16).fill(7);
const DOCS_KEY = toHex(DOCS);
const IDENTITY = new Uint8Array(33).fill(1);
const ENC = new Uint8Array(32).fill(2);
const CODE = new Uint8Array([0xab, 0xcd]);
const CONTACT = { key: toHex(IDENTITY), identityPublicKey: IDENTITY };
const FRAGMENT = 'a-bearer-fragment';
const DEADLINE = 1_700_000_000_000n;
const NO_LINKS: SharingInviteLinksDescriptor = {
  live: false,
  expired: false,
  expiresAt: null,
  spent: 0,
};

function grantsFor(scopeKey: string): readonly GrantRow[] | null {
  return sharingFor(sharingStore.getState(), scopeKey)?.grants ?? null;
}

/** One engine sharing read: the book always holds the one contact under test. */
function view(grants: Permission[], links: SharingInviteLinksDescriptor): SharingDescriptor {
  return {
    scope: DOCS,
    contacts: [{ identityPublicKey: IDENTITY }],
    state: {
      grants: grants.map((permission) => ({
        recipientIdentityPublicKey: IDENTITY,
        permission,
      })),
      // A share of the folder mints a scope at it, which a second share cannot.
      canMintShare: grants.length === 0 && !links.live,
      inviteLinks: links,
    },
  };
}

/**
 * The grant surface the hook drives, refusing whichever command a test names.
 * `sharing` answers with whatever the ledger holds *now*, so a test states the
 * engine's truth rather than what the hook happened to send.
 */
function sharingEngine(
  refusals: Partial<Record<SharingCommand, Error>> = {},
  held: SharingInviteLinksDescriptor = NO_LINKS
) {
  const answer = <T,>(name: SharingCommand, value: T) =>
    refusals[name] === undefined ? Promise.resolve(value) : Promise.reject(refusals[name]);

  const ledger: Permission[] = [];
  const links: SharingInviteLinksDescriptor = { ...held };
  const facade = {
    subscribe: (_listener: (event: EventDescriptor) => void) => () => undefined,
    snapshot: () => new Promise<never>(() => undefined),
    setFocus: () => Promise.resolve(),
    sharing: vi.fn(() => answer('read', view(ledger, { ...links }))),
    importContact: vi.fn(() =>
      answer('importContact', {
        kind: 'contactImported' as const,
        identityPublicKey: IDENTITY,
        encPublicKey: ENC,
      })
    ),
    grant: vi.fn((_scope: Uint8Array, _key: Uint8Array, permission: Permission) => {
      if (refusals.grant === undefined) ledger.splice(0, ledger.length, permission);
      return answer('grant', { kind: 'done' as const });
    }),
    revoke: vi.fn(() => {
      if (refusals.revoke === undefined) ledger.length = 0;
      return answer('revoke', { kind: 'done' as const });
    }),
    downgrade: vi.fn(() => {
      if (refusals.downgrade === undefined) ledger.splice(0, ledger.length, 'read');
      return answer('downgrade', { kind: 'done' as const });
    }),
    createInviteLink: vi.fn(() => {
      if (refusals.createInviteLink === undefined) {
        links.live = true;
        links.expiresAt = DEADLINE;
      }
      return answer('createInviteLink', { kind: 'inviteLinkMinted' as const, fragment: FRAGMENT });
    }),
    revokeInviteLink: vi.fn(() => {
      if (refusals.revokeInviteLink === undefined) {
        links.live = false;
        links.expiresAt = null;
      }
      return answer('revokeInviteLink', { kind: 'done' as const });
    }),
    pruneInviteLinks: vi.fn(() => {
      if (refusals.pruneInviteLinks === undefined) links.spent = 0;
      return answer('pruneInviteLinks', { kind: 'done' as const });
    }),
    convertInviteClaims: vi.fn(() => {
      if (refusals.convertInviteClaims === undefined) ledger.push('read');
      return answer('convertInviteClaims', { kind: 'done' as const });
    }),
  };

  const client = {
    facade,
    reportFocus: () => undefined,
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;

  return { client, facade };
}

function mount(client: EngineClient) {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <EngineProvider createClient={() => client}>{children}</EngineProvider>
  );
  return renderHook(() => useSharingActions(DOCS), { wrapper });
}

afterEach(() => sharingStore.clear());

describe('reading', () => {
  it('names the scope it was asked for and stores the view the engine answered', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);

    await expect(result.current.reload()).resolves.toBe(true);

    expect(engine.facade.sharing).toHaveBeenCalledWith(DOCS);
    expect(sharingStore.getState().contacts).toEqual([CONTACT]);
    expect(grantsFor(DOCS_KEY)).toEqual([]);
  });

  it('reports a refused read in the engine words, storing nothing', async () => {
    const engine = sharingEngine({ read: new EngineRequestError('the scope would not resolve') });
    const { result } = mount(engine.client);

    await expect(result.current.reload()).resolves.toBe(false);

    expect(sharingStore.getState().contacts).toEqual([]);
    await waitFor(() => expect(result.current.error).toBe('the scope would not resolve'));
  });
});

describe('contact import', () => {
  it('hands the engine the code, then holds the book the engine re-read', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);

    await expect(result.current.importContact(CODE)).resolves.toBe(true);

    expect(engine.facade.importContact).toHaveBeenCalledWith(CODE);
    expect(sharingStore.getState().contacts).toEqual([CONTACT]);
  });

  it('re-reads nothing for a code the engine refused, and reports its words', async () => {
    const refusal = new EngineRequestError('contact binding did not verify', 'trustViolation');
    const engine = sharingEngine({ importContact: refusal });
    const { result } = mount(engine.client);

    await expect(result.current.importContact(CODE)).resolves.toBe(false);

    expect(engine.facade.sharing).not.toHaveBeenCalled();
    expect(sharingStore.getState().contacts).toEqual([]);
    await waitFor(() => expect(result.current.error).toBe('contact binding did not verify'));
  });
});

describe('grant commands', () => {
  it('lists the row the engine reports after the grant, not the one it was sent', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);

    await expect(result.current.grant(CONTACT, 'write')).resolves.toBe(true);

    expect(engine.facade.grant).toHaveBeenCalledWith(DOCS, IDENTITY, 'write');
    expect(grantsFor(DOCS_KEY)).toEqual([{ contact: CONTACT, permission: 'write' }]);
  });

  it('lists no row for a grant the engine refused', async () => {
    const engine = sharingEngine({ grant: new EngineRequestError('recipient is the owner') });
    const { result } = mount(engine.client);

    await expect(result.current.grant(CONTACT, 'read')).resolves.toBe(false);

    // A refused grant re-reads nothing, so the scope still has no ledger at all
    // — not an empty one, which would claim the engine answered.
    expect(grantsFor(DOCS_KEY)).toBeNull();
    await waitFor(() => expect(result.current.error).toBe('recipient is the owner'));
  });

  it('drops the row the engine revoked', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);
    await result.current.grant(CONTACT, 'read');

    await expect(result.current.revoke(CONTACT)).resolves.toBe(true);

    expect(engine.facade.revoke).toHaveBeenCalledWith(DOCS, IDENTITY);
    expect(grantsFor(DOCS_KEY)).toEqual([]);
  });

  it('keeps the row a refused revoke left standing in the ledger', async () => {
    const engine = sharingEngine({ revoke: new EngineRequestError('the publish was refused') });
    const { result } = mount(engine.client);
    await result.current.grant(CONTACT, 'read');

    await expect(result.current.revoke(CONTACT)).resolves.toBe(false);

    expect(grantsFor(DOCS_KEY)).toEqual([{ contact: CONTACT, permission: 'read' }]);
    await waitFor(() => expect(result.current.error).toBe('the publish was refused'));
  });

  it('shows the downgraded row at the permission the ledger now commits', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);
    await result.current.grant(CONTACT, 'write');

    await expect(result.current.downgrade(CONTACT)).resolves.toBe(true);

    expect(engine.facade.downgrade).toHaveBeenCalledWith(DOCS, IDENTITY);
    expect(grantsFor(DOCS_KEY)).toEqual([{ contact: CONTACT, permission: 'read' }]);
  });

  it('keeps the write grant a refused downgrade left standing', async () => {
    const engine = sharingEngine({ downgrade: new EngineRequestError('publish refused') });
    const { result } = mount(engine.client);
    await result.current.grant(CONTACT, 'write');

    await expect(result.current.downgrade(CONTACT)).resolves.toBe(false);

    expect(grantsFor(DOCS_KEY)).toEqual([{ contact: CONTACT, permission: 'write' }]);
  });
});

describe('invite link commands', () => {
  const linksNow = () => sharingFor(sharingStore.getState(), DOCS_KEY)?.inviteLinks ?? null;

  it('hands back the minted fragment and shows the link the engine now reports', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);

    await expect(result.current.createInviteLink('read', DEADLINE)).resolves.toBe(FRAGMENT);

    expect(engine.facade.createInviteLink).toHaveBeenCalledWith(DOCS, 'read', DEADLINE);
    expect(linksNow()).toEqual({ ...NO_LINKS, live: true, expiresAt: DEADLINE });
  });

  it('hands back no fragment for a mint the engine refused', async () => {
    const refusal = new EngineRequestError(
      'unsupported target: invite-target-already-names-a-scope'
    );
    const engine = sharingEngine({ createInviteLink: refusal });
    const { result } = mount(engine.client);

    await expect(result.current.createInviteLink('read')).resolves.toBeNull();
    await waitFor(() => expect(result.current.error).toBe(refusal.message));
  });

  it('shows the link gone once the engine cut it', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);
    await result.current.createInviteLink('read', DEADLINE);

    await expect(result.current.revokeInviteLink()).resolves.toBe(true);

    expect(engine.facade.revokeInviteLink).toHaveBeenCalledWith(DOCS);
    expect(linksNow()).toEqual(NO_LINKS);
  });

  it('keeps the link standing when the engine refused to cut it', async () => {
    const engine = sharingEngine({ revokeInviteLink: new EngineRequestError('publish refused') });
    const { result } = mount(engine.client);
    await result.current.createInviteLink('read', DEADLINE);

    await expect(result.current.revokeInviteLink()).resolves.toBe(false);

    expect(linksNow()).toEqual({ ...NO_LINKS, live: true, expiresAt: DEADLINE });
  });

  it('drops the spent records the engine pruned', async () => {
    const engine = sharingEngine({}, { live: false, expired: false, expiresAt: null, spent: 2 });
    const { result } = mount(engine.client);

    await expect(result.current.pruneInviteLinks()).resolves.toBe(true);

    expect(engine.facade.pruneInviteLinks).toHaveBeenCalledWith(DOCS);
    expect(linksNow()?.spent).toBe(0);
  });

  it('lists the grant a conversion committed, not the claim it was sent', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);
    await result.current.createInviteLink('read', DEADLINE);

    await expect(result.current.convertInviteClaims()).resolves.toBe(true);

    expect(engine.facade.convertInviteClaims).toHaveBeenCalledWith(DOCS);
    expect(grantsFor(DOCS_KEY)).toEqual([{ contact: CONTACT, permission: 'read' }]);
  });
});
