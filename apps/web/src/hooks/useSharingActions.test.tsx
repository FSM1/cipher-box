import type { ReactNode } from 'react';
import { EngineRequestError, toHex } from '@cipherbox/client';
import type {
  EngineClient,
  EventDescriptor,
  Permission,
  SharingDescriptor,
  SharingGrantDescriptor,
  SharingInviteLinkDescriptor,
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
const NO_LINKS: SharingInviteLinkDescriptor[] = [];
const FINGERPRINT = 'fp-ada';
/** The link a mint commits, as the engine then reports it. */
const MINTED: SharingInviteLinkDescriptor = {
  tag: new Uint8Array(32).fill(0x7a),
  permission: 'read',
  expiresAt: DEADLINE,
  expired: false,
  admissionCap: 5,
  pendingClaims: 0,
  contactBudgetFull: false,
  refusedClaims: 0,
};

/** The row the one contact under test reads as, direct and unnamed. */
function row(permission: Permission): GrantRow {
  return { contact: CONTACT, permission, name: null, viaLink: null, fingerprint: FINGERPRINT };
}

function grantsFor(scopeKey: string): readonly GrantRow[] | null {
  return sharingFor(sharingStore.getState(), scopeKey)?.grants ?? null;
}

/** One engine sharing read: the book always holds the one contact under test. */
function view(
  grants: Permission[],
  links: SharingInviteLinkDescriptor[],
  names: SharingGrantDescriptor['granteeName'][] = []
): SharingDescriptor {
  return {
    scope: DOCS,
    contacts: [{ identityPublicKey: IDENTITY, cachedName: null }],
    ownContactCode: new Uint8Array([0xc0, 0xde]),
    state: {
      grants: grants.map((permission) => ({
        recipientIdentityPublicKey: IDENTITY,
        permission,
        granteeName: names[0] ?? null,
        viaLink: null,
      })),
      grantRefusal: null,
      inviteLinkRefusal: null,
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
  held: SharingInviteLinkDescriptor[] = NO_LINKS
) {
  const answer = <T,>(name: SharingCommand, value: T) =>
    refusals[name] === undefined ? Promise.resolve(value) : Promise.reject(refusals[name]);

  const ledger: Permission[] = [];
  const names: SharingGrantDescriptor['granteeName'][] = [];
  const links: SharingInviteLinkDescriptor[] = [...held];
  const listeners = new Set<(event: EventDescriptor) => void>();
  const facade = {
    subscribe: (listener: (event: EventDescriptor) => void) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    snapshot: () => new Promise<never>(() => undefined),
    setFocus: () => Promise.resolve(),
    sharing: vi.fn(() =>
      answer(
        'read',
        view(
          ledger,
          links.map((link) => ({ ...link })),
          names
        )
      )
    ),
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
    changePermission: vi.fn((_scope: Uint8Array, _key: Uint8Array, permission: Permission) => {
      if (refusals.changePermission === undefined) ledger.splice(0, ledger.length, permission);
      return answer('changePermission', { kind: 'done' as const });
    }),
    renameGrantee: vi.fn((_scope: Uint8Array, _key: Uint8Array, name: string) => {
      if (refusals.renameGrantee === undefined) names.splice(0, 1, { name, source: 'owner' });
      return answer('renameGrantee', { kind: 'done' as const });
    }),
    identityFingerprint: vi.fn(() => Promise.resolve(FINGERPRINT)),
    createInviteLink: vi.fn(() => {
      if (refusals.createInviteLink === undefined) links.push({ ...MINTED });
      return answer('createInviteLink', { kind: 'inviteLinkMinted' as const, fragment: FRAGMENT });
    }),
    revokeInviteLink: vi.fn((_scope: Uint8Array, linkTag?: Uint8Array) => {
      if (refusals.revokeInviteLink === undefined) {
        const kept =
          linkTag === undefined ? [] : links.filter((link) => toHex(link.tag) !== toHex(linkTag));
        links.splice(0, links.length, ...kept);
      }
      return answer('revokeInviteLink', { kind: 'done' as const });
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

  const emit = (event: EventDescriptor) => listeners.forEach((listener) => listener(event));
  return { client, facade, links, emit };
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

    await expect(result.current.open()).resolves.toBe(true);

    expect(engine.facade.sharing).toHaveBeenCalledWith(DOCS);
    expect(sharingStore.getState().contacts).toEqual([CONTACT]);
    expect(grantsFor(DOCS_KEY)).toEqual([]);
  });

  it('converts nothing on open where the scope carries no link', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);

    await expect(result.current.open()).resolves.toBe(true);

    expect(engine.facade.convertInviteClaims).not.toHaveBeenCalled();
  });

  it('converts the waiting claims on open where the scope carries a link', async () => {
    const engine = sharingEngine({}, [MINTED]);
    const { result } = mount(engine.client);

    await expect(result.current.open()).resolves.toBe(true);

    expect(engine.facade.convertInviteClaims).toHaveBeenCalledWith(DOCS);
    expect(grantsFor(DOCS_KEY)).toEqual([row('read')]);
  });

  it('keeps the read and reports a conversion the engine refused', async () => {
    const refusal = new EngineRequestError('seam error: the mailbox did not answer');
    const engine = sharingEngine({ convertInviteClaims: refusal }, [MINTED]);
    const { result } = mount(engine.client);

    await expect(result.current.open()).resolves.toBe(false);

    expect(grantsFor(DOCS_KEY)).toEqual([]);
    await waitFor(() => expect(result.current.error).toBe(refusal.message));
  });

  it('reports nothing on open while another conversion pass runs', async () => {
    const running = new EngineRequestError('seam error: a-conversion-pass-is-running', 'seam');
    const engine = sharingEngine({ convertInviteClaims: running }, [MINTED]);
    const { result } = mount(engine.client);

    await expect(result.current.open()).resolves.toBe(true);

    expect(engine.facade.convertInviteClaims).toHaveBeenCalledWith(DOCS);
    expect(result.current.error).toBeNull();
  });

  it('re-reads the view on a snapshot update, so a pass that moved only the counts shows', async () => {
    const running = new EngineRequestError('seam error: a-conversion-pass-is-running', 'seam');
    const engine = sharingEngine({ convertInviteClaims: running }, [MINTED]);
    const { result } = mount(engine.client);
    await expect(result.current.open()).resolves.toBe(true);
    const pendingClaims = () =>
      sharingFor(sharingStore.getState(), DOCS_KEY)?.inviteLinks[0]?.pendingClaims;
    expect(pendingClaims()).toBe(0);

    engine.links.splice(0, 1, { ...MINTED, pendingClaims: 2 });
    engine.emit({ kind: 'snapshotUpdated' });

    await waitFor(() => expect(pendingClaims()).toBe(2));
    expect(engine.facade.sharing).toHaveBeenCalledTimes(2);
  });

  it('reads nothing on a snapshot update where the scope carries no link', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);
    await expect(result.current.open()).resolves.toBe(true);

    engine.emit({ kind: 'snapshotUpdated' });
    await new Promise((settle) => setTimeout(settle, 0));

    expect(engine.facade.sharing).toHaveBeenCalledTimes(1);
  });

  it("keeps a command's view when an older event read finishes after it", async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);
    await result.current.grant(CONTACT, 'write');
    let finishStale: (stale: SharingDescriptor) => void = () => undefined;
    engine.facade.sharing.mockImplementationOnce(
      () => new Promise<SharingDescriptor>((settle) => (finishStale = settle))
    );

    engine.emit({ kind: 'granteeJoined', scopeRoot: DOCS, name: 'Ada', fingerprint: FINGERPRINT });
    await expect(result.current.changePermission(CONTACT, 'read')).resolves.toBe(true);
    expect(grantsFor(DOCS_KEY)).toEqual([row('read')]);

    finishStale(view(['write'], NO_LINKS));
    await new Promise((settle) => setTimeout(settle, 0));

    expect(engine.facade.sharing).toHaveBeenCalledTimes(3);
    expect(grantsFor(DOCS_KEY)).toEqual([row('read')]);
  });

  it('reads a row with no fingerprint where the engine forms none for its key', async () => {
    const engine = sharingEngine();
    engine.facade.identityFingerprint.mockImplementation(() =>
      Promise.reject(new EngineRequestError('invalid identity public key'))
    );
    const { result } = mount(engine.client);

    await expect(result.current.grant(CONTACT, 'read')).resolves.toBe(true);

    expect(grantsFor(DOCS_KEY)).toEqual([{ ...row('read'), fingerprint: null }]);
  });

  it('reports a refused read in the engine words, storing nothing', async () => {
    const engine = sharingEngine({ read: new EngineRequestError('the scope would not resolve') });
    const { result } = mount(engine.client);

    await expect(result.current.open()).resolves.toBe(false);

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
    expect(grantsFor(DOCS_KEY)).toEqual([row('write')]);
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

    expect(grantsFor(DOCS_KEY)).toEqual([row('read')]);
    await waitFor(() => expect(result.current.error).toBe('the publish was refused'));
  });

  it('shows the changed row at the permission the ledger now commits', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);
    await result.current.grant(CONTACT, 'write');

    await expect(result.current.changePermission(CONTACT, 'read')).resolves.toBe(true);

    expect(engine.facade.changePermission).toHaveBeenCalledWith(DOCS, IDENTITY, 'read');
    expect(grantsFor(DOCS_KEY)).toEqual([row('read')]);
  });

  it('keeps the write grant a refused change left standing', async () => {
    const engine = sharingEngine({ changePermission: new EngineRequestError('publish refused') });
    const { result } = mount(engine.client);
    await result.current.grant(CONTACT, 'write');

    await expect(result.current.changePermission(CONTACT, 'read')).resolves.toBe(false);

    expect(grantsFor(DOCS_KEY)).toEqual([row('write')]);
  });

  it('shows the name the engine committed after a rename', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);
    await result.current.grant(CONTACT, 'read');

    await expect(result.current.renameGrantee(CONTACT, 'Ada')).resolves.toBe(true);

    expect(engine.facade.renameGrantee).toHaveBeenCalledWith(DOCS, IDENTITY, 'Ada');
    expect(grantsFor(DOCS_KEY)).toEqual([
      { ...row('read'), name: { name: 'Ada', source: 'owner' } },
    ]);
  });
});

describe('invite link commands', () => {
  const linksNow = () => sharingFor(sharingStore.getState(), DOCS_KEY)?.inviteLinks ?? null;

  it('hands back the minted fragment and shows the link the engine now reports', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);

    await expect(result.current.createInviteLink('read', DEADLINE, 'Ada', 5)).resolves.toBe(
      FRAGMENT
    );

    expect(engine.facade.createInviteLink).toHaveBeenCalledWith(DOCS, 'read', DEADLINE, 'Ada', 5);
    expect(linksNow()).toEqual([MINTED]);
  });

  it('hands back no fragment for a mint the engine refused', async () => {
    const refusal = new EngineRequestError('unsupported target: invite-target-index-lost-a-root');
    const engine = sharingEngine({ createInviteLink: refusal });
    const { result } = mount(engine.client);

    await expect(result.current.createInviteLink('read', DEADLINE, '', 25)).resolves.toBeNull();
    await waitFor(() => expect(result.current.error).toBe(refusal.message));
  });

  it('shows the link gone once the engine cut it', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);
    await result.current.createInviteLink('read', DEADLINE, '', 25);

    await expect(
      result.current.revokeInviteLink(MINTED.tag, { removeGrantees: false })
    ).resolves.toBe(true);

    expect(engine.facade.revokeInviteLink).toHaveBeenCalledWith(DOCS, MINTED.tag, false);
    expect(linksNow()).toEqual(NO_LINKS);
  });

  it('keeps the link standing when the engine refused to cut it', async () => {
    const engine = sharingEngine({ revokeInviteLink: new EngineRequestError('publish refused') });
    const { result } = mount(engine.client);
    await result.current.createInviteLink('read', DEADLINE, '', 25);

    await expect(
      result.current.revokeInviteLink(MINTED.tag, { removeGrantees: false })
    ).resolves.toBe(false);

    expect(linksNow()).toEqual([MINTED]);
  });

  it('asks the engine to cut the people who joined when the owner chose it', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);
    await result.current.createInviteLink('read', DEADLINE, '', 25);

    await expect(
      result.current.revokeInviteLink(MINTED.tag, { removeGrantees: true })
    ).resolves.toBe(true);

    expect(engine.facade.revokeInviteLink).toHaveBeenCalledWith(DOCS, MINTED.tag, true);
    expect(linksNow()).toEqual(NO_LINKS);
  });
});
