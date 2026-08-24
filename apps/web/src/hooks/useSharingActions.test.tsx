import type { ReactNode } from 'react';
import { EngineRequestError, toHex } from '@cipherbox/client';
import type { EngineClient, EventDescriptor } from '@cipherbox/client';
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

/** The grant surface the hook drives, refusing whichever command a test names. */
function sharingEngine(refusals: Partial<Record<SharingCommand, Error>> = {}) {
  const listeners = new Set<(event: EventDescriptor) => void>();
  const answer = <T,>(name: SharingCommand, value: T) =>
    refusals[name] === undefined ? Promise.resolve(value) : Promise.reject(refusals[name]);

  const facade = {
    subscribe(listener: (event: EventDescriptor) => void) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    snapshot: () => new Promise<never>(() => undefined),
    setFocus: () => Promise.resolve(),
    importContact: vi.fn(() =>
      answer('importContact', {
        kind: 'contactImported' as const,
        identityPublicKey: IDENTITY,
        encPublicKey: ENC,
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

function mount(client: EngineClient) {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <EngineProvider createClient={() => client}>{children}</EngineProvider>
  );
  return renderHook(() => useSharingActions(), { wrapper });
}

afterEach(() => sharingStore.clear());

describe('contact import', () => {
  it('hands the engine the code and records the contact it verified', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);

    await expect(result.current.importContact(CODE)).resolves.toBe(true);

    expect(engine.facade.importContact).toHaveBeenCalledWith(CODE);
    expect(sharingStore.getState().contacts).toEqual([
      { key: '01'.repeat(33), identityPublicKey: IDENTITY },
    ]);
  });

  it('records no contact for a code the engine refused, and reports its words', async () => {
    const refusal = new EngineRequestError('contact binding did not verify', 'trustViolation');
    const engine = sharingEngine({ importContact: refusal });
    const { result } = mount(engine.client);

    await expect(result.current.importContact(CODE)).resolves.toBe(false);

    expect(sharingStore.getState().contacts).toEqual([]);
    await waitFor(() => expect(result.current.error).toBe('contact binding did not verify'));
  });
});

describe('grant commands', () => {
  const contact = { key: '01'.repeat(33), identityPublicKey: IDENTITY };

  it('lists a grant the engine accepted, naming the recipient by identity key', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);

    await expect(result.current.grant(DOCS, contact, 'write')).resolves.toBe(true);

    expect(engine.facade.grant).toHaveBeenCalledWith(DOCS, IDENTITY, 'write');
    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([
      { contact, permission: 'write' },
    ]);
  });

  it('lists no grant the engine refused', async () => {
    const engine = sharingEngine({ grant: new EngineRequestError('recipient is the owner') });
    const { result } = mount(engine.client);

    await expect(result.current.grant(DOCS, contact, 'read')).resolves.toBe(false);

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([]);
    await waitFor(() => expect(result.current.error).toBe('recipient is the owner'));
  });

  it('drops the row the engine revoked', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);
    await result.current.grant(DOCS, contact, 'read');

    await expect(result.current.revoke(DOCS, contact)).resolves.toBe(true);

    expect(engine.facade.revoke).toHaveBeenCalledWith(DOCS, IDENTITY);
    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([]);
  });

  it('keeps the row a refused revoke left standing', async () => {
    const engine = sharingEngine({ revoke: new EngineRequestError('the publish was refused') });
    const { result } = mount(engine.client);
    await result.current.grant(DOCS, contact, 'read');

    await expect(result.current.revoke(DOCS, contact)).resolves.toBe(false);

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([{ contact, permission: 'read' }]);
    await waitFor(() => expect(result.current.error).toBe('the publish was refused'));
  });

  it('keeps the row a downgrade landed on, at read', async () => {
    const engine = sharingEngine();
    const { result } = mount(engine.client);
    await result.current.grant(DOCS, contact, 'write');

    await expect(result.current.downgrade(DOCS, contact)).resolves.toBe(true);

    expect(engine.facade.downgrade).toHaveBeenCalledWith(DOCS, IDENTITY);
    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([{ contact, permission: 'read' }]);
  });

  it('keeps the write grant a refused downgrade left standing', async () => {
    const engine = sharingEngine({ downgrade: new EngineRequestError('publish refused') });
    const { result } = mount(engine.client);
    await result.current.grant(DOCS, contact, 'write');

    await expect(result.current.downgrade(DOCS, contact)).resolves.toBe(false);

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([
      { contact, permission: 'write' },
    ]);
  });
});
