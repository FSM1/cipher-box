import type { ReactNode } from 'react';
import { EngineRequestError, toHex } from '@cipherbox/client';
import type {
  EngineClient,
  EventDescriptor,
  Permission,
  SharingDescriptor,
} from '@cipherbox/client';
import { renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EngineProvider } from '../providers/EngineProvider';
import { grantsFor, sharingStore } from '../stores/sharing.store';
import { useSharingActions, type SharingCommand } from './useSharingActions';

const DOCS = new Uint8Array(16).fill(7);
const DOCS_KEY = toHex(DOCS);
const IDENTITY = new Uint8Array(33).fill(1);
const ENC = new Uint8Array(32).fill(2);
const CODE = new Uint8Array([0xab, 0xcd]);
const CONTACT = { key: toHex(IDENTITY), identityPublicKey: IDENTITY };

/** One engine sharing read: the book always holds the one contact under test. */
function view(grants: Permission[]): SharingDescriptor {
  return {
    scope: DOCS,
    contacts: [{ identityPublicKey: IDENTITY, encryptionPublicKey: ENC }],
    grants: grants.map((permission) => ({
      recipientIdentityPublicKey: IDENTITY,
      permission,
    })),
  };
}

/**
 * The grant surface the hook drives, refusing whichever command a test names.
 * `sharing` answers with whatever the ledger holds *now*, so a test states the
 * engine's truth rather than what the hook happened to send.
 */
function sharingEngine(refusals: Partial<Record<SharingCommand, Error>> = {}) {
  const answer = <T,>(name: SharingCommand, value: T) =>
    refusals[name] === undefined ? Promise.resolve(value) : Promise.reject(refusals[name]);

  const ledger: Permission[] = [];
  const facade = {
    subscribe: (_listener: (event: EventDescriptor) => void) => () => undefined,
    snapshot: () => new Promise<never>(() => undefined),
    setFocus: () => Promise.resolve(),
    sharing: vi.fn(() => answer('read', view(ledger))),
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
    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([]);
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
    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([
      { contact: CONTACT, permission: 'write' },
    ]);
  });

  it('lists no row for a grant the engine refused', async () => {
    const engine = sharingEngine({ grant: new EngineRequestError('recipient is the owner') });
    const { result } = mount(engine.client);

    await expect(result.current.grant(CONTACT, 'read')).resolves.toBe(false);

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([]);
    await waitFor(() => expect(result.current.error).toBe('recipient is the owner'));
  });

  it('drops the row the engine revoked', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);
    await result.current.grant(CONTACT, 'read');

    await expect(result.current.revoke(CONTACT)).resolves.toBe(true);

    expect(engine.facade.revoke).toHaveBeenCalledWith(DOCS, IDENTITY);
    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([]);
  });

  it('keeps the row a refused revoke left standing in the ledger', async () => {
    const engine = sharingEngine({ revoke: new EngineRequestError('the publish was refused') });
    const { result } = mount(engine.client);
    await result.current.grant(CONTACT, 'read');

    await expect(result.current.revoke(CONTACT)).resolves.toBe(false);

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([
      { contact: CONTACT, permission: 'read' },
    ]);
    await waitFor(() => expect(result.current.error).toBe('the publish was refused'));
  });

  it('shows the downgraded row at the permission the ledger now commits', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);
    await result.current.grant(CONTACT, 'write');

    await expect(result.current.downgrade(CONTACT)).resolves.toBe(true);

    expect(engine.facade.downgrade).toHaveBeenCalledWith(DOCS, IDENTITY);
    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([
      { contact: CONTACT, permission: 'read' },
    ]);
  });

  it('keeps the write grant a refused downgrade left standing', async () => {
    const engine = sharingEngine({ downgrade: new EngineRequestError('publish refused') });
    const { result } = mount(engine.client);
    await result.current.grant(CONTACT, 'write');

    await expect(result.current.downgrade(CONTACT)).resolves.toBe(false);

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([
      { contact: CONTACT, permission: 'write' },
    ]);
  });
});
