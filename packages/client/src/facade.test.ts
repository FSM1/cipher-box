import { readFileSync } from 'node:fs';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { EngineFacade } from './facade.js';
import {
  byoSettings,
  emptyBin,
  emptySharing,
  emptySnapshot,
  emptyVaultStorage,
  FAKE_SIWE_NONCE,
  TEST_ACCOUNT_ID,
} from './testkit.js';
import type { EngineEventListener, EngineTransport } from './transport.js';
import { MAX_FRAGMENT_CHARS } from './worker/protocol.js';
import type {
  AuthMethodDescriptor,
  BinDescriptor,
  CommandDescriptor,
  CommandOutcomeDescriptor,
  DeviceRendezvousResult,
  DeviceRendezvousStep,
  OpenedStream,
  PendingApprovalDescriptor,
  ReceivedShareDescriptor,
  RegisteredDeviceDescriptor,
  SharingDescriptor,
  SiweIntent,
  SnapshotDescriptor,
  StreamHandle,
  VaultStorageDescriptor,
  WriteHandle,
  WriteTarget,
} from './worker/protocol.js';

/** Stands in for the engine's opaque capability; the facade reads none of it. */
const MINTED_FRAGMENT = 'a-minted-fragment';

/**
 * The names the engine's committed vector file refuses, read from the one file
 * the Rust law and the desktop projection answer against.
 */
function unlawfulNames(): string[] {
  const path = new URL('../../../crates/engine/name-law/vectors.json', import.meta.url);
  const { names } = JSON.parse(readFileSync(path, 'utf8')) as {
    names?: Array<{ name: string; verdict: string }>;
  };
  const refused = (names ?? []).filter((row) => row.verdict !== 'accept').map((row) => row.name);
  if (refused.length === 0) throw new Error('the name-law vectors lost their refused rows');
  return refused;
}

/** A transport whose engine answers every command with a minted link. */
function mintingTransport(): FakeTransport {
  const transport = new FakeTransport();
  transport.outcome = { kind: 'inviteLinkMinted', fragment: MINTED_FRAGMENT };
  return transport;
}

class FakeTransport implements EngineTransport {
  started: ArrayBuffer[] = [];
  commands: CommandDescriptor[] = [];
  snapshots: Uint8Array[] = [];
  sharingReads: Array<Uint8Array | null> = [];
  receivedShareReads = 0;
  binReads = 0;
  vaultStorageReads = 0;
  authMethodReads = 0;
  deviceReads = 0;
  pendingApprovalReads = 0;
  registrationChallenges: string[] = [];
  rendezvousSteps: DeviceRendezvousStep[] = [];
  downloads: Uint8Array[] = [];
  siweChallenges = 0;
  siweChallengeIntents: SiweIntent[] = [];
  opened: Uint8Array[] = [];
  reads: Array<{ handle: StreamHandle; offset: number; length: number }> = [];
  closedStreams: StreamHandle[] = [];
  beginWrites: Array<{ target: WriteTarget; size: number }> = [];
  chunks: Array<{ handle: WriteHandle; chunk: ArrayBuffer }> = [];
  commits: WriteHandle[] = [];
  aborts: WriteHandle[] = [];
  listeners: EngineEventListener[] = [];
  closed = false;
  /** The account the engine holds; `null` once no session backs it. */
  account: string | null = TEST_ACCOUNT_ID;
  /** Every container gone by the time the worker was torn down. */
  goneAtClose: string[] = [];

  constructor(private readonly origin: { gone: string[] } = { gone: [] }) {}

  start(secret: ArrayBuffer): Promise<void> {
    this.started.push(secret);
    return Promise.resolve();
  }

  signedInAccount(): string | null {
    return this.account;
  }

  /** What the next `command` resolves with; the engine answers `done` by default. */
  outcome: CommandOutcomeDescriptor = { kind: 'done' };

  command(command: CommandDescriptor): Promise<CommandOutcomeDescriptor> {
    this.commands.push(command);
    return Promise.resolve(this.outcome);
  }

  beginWrite(target: WriteTarget, size: number): Promise<WriteHandle> {
    this.beginWrites.push({ target, size });
    return Promise.resolve(7n);
  }

  pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void> {
    this.chunks.push({ handle, chunk });
    return Promise.resolve();
  }

  commitWrite(handle: WriteHandle): Promise<bigint> {
    this.commits.push(handle);
    return Promise.resolve(99n);
  }

  abortWrite(handle: WriteHandle): Promise<void> {
    this.aborts.push(handle);
    return Promise.resolve();
  }

  snapshot(folder: Uint8Array): Promise<SnapshotDescriptor> {
    this.snapshots.push(folder);
    return Promise.resolve(emptySnapshot(folder));
  }

  sharing(scope: Uint8Array | null): Promise<SharingDescriptor> {
    this.sharingReads.push(scope);
    return Promise.resolve(emptySharing(scope ?? undefined));
  }

  receivedShares(): Promise<ReceivedShareDescriptor[]> {
    this.receivedShareReads += 1;
    return Promise.resolve([]);
  }

  bin(): Promise<BinDescriptor> {
    this.binReads += 1;
    return Promise.resolve(emptyBin());
  }

  vaultStorage(): Promise<VaultStorageDescriptor> {
    this.vaultStorageReads += 1;
    return Promise.resolve(emptyVaultStorage());
  }

  authMethods(): Promise<AuthMethodDescriptor[]> {
    this.authMethodReads += 1;
    return Promise.resolve([]);
  }

  devices(): Promise<RegisteredDeviceDescriptor[]> {
    this.deviceReads += 1;
    return Promise.resolve([]);
  }

  deviceRegistrationChallenge(devicePublicKey: string): Promise<Uint8Array> {
    this.registrationChallenges.push(devicePublicKey);
    return Promise.resolve(Uint8Array.of(1, 2, 3));
  }

  pendingApprovals(): Promise<PendingApprovalDescriptor[]> {
    this.pendingApprovalReads += 1;
    return Promise.resolve([]);
  }

  deviceRendezvous(step: DeviceRendezvousStep): Promise<DeviceRendezvousResult> {
    this.rendezvousSteps.push(step);
    return Promise.resolve({ kind: 'factor', factorKey: Uint8Array.of(7, 7) });
  }

  siweChallenge(intent: SiweIntent): Promise<string> {
    this.siweChallenges += 1;
    this.siweChallengeIntents.push(intent);
    return Promise.resolve(FAKE_SIWE_NONCE);
  }

  download(node: Uint8Array): Promise<ArrayBuffer> {
    this.downloads.push(node);
    return Promise.resolve(new Uint8Array([1, 2, 3]).buffer);
  }

  openContentStream(node: Uint8Array): Promise<OpenedStream> {
    this.opened.push(node);
    return Promise.resolve({ handle: 3n, size: 4096 });
  }

  readStream(handle: StreamHandle, offset: number, length: number): Promise<ArrayBuffer> {
    this.reads.push({ handle, offset, length });
    return Promise.resolve(new Uint8Array([4, 5]).buffer);
  }

  closeStream(handle: StreamHandle): Promise<void> {
    this.closedStreams.push(handle);
    return Promise.resolve();
  }

  subscribe(listener: EngineEventListener): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((entry) => entry !== listener);
    };
  }

  close(): void {
    this.closed = true;
    this.goneAtClose = [...this.origin.gone];
  }
}

/**
 * A stub origin holding `containers`, dropping each name a sweep takes. The
 * names that survive are what the AC reads.
 */
function stubOrigin(containers: string[]): { containers: string[]; gone: string[] } {
  const origin = { containers, gone: [] as string[] };
  const take = (name: string): void => {
    origin.containers = origin.containers.filter((entry) => entry !== name);
    origin.gone.push(name);
  };
  vi.stubGlobal('indexedDB', {
    deleteDatabase: (name: string) => {
      const request: { onsuccess?: () => void } = {};
      queueMicrotask(() => {
        take(name);
        request.onsuccess?.();
      });
      return request as unknown as IDBOpenDBRequest;
    },
  });
  vi.stubGlobal('navigator', {
    storage: {
      getDirectory: () =>
        Promise.resolve({
          removeEntry: (name: string) => {
            take(name);
            return Promise.resolve();
          },
        }),
    },
  });
  return origin;
}

afterEach(() => vi.unstubAllGlobals());

describe('EngineFacade', () => {
  it('forwards the login secret to the transport on start', async () => {
    const transport = new FakeTransport();
    const secret = new Uint8Array([9, 9, 9]).buffer;
    await new EngineFacade(transport).start(secret, TEST_ACCOUNT_ID);
    expect(transport.started).toEqual([secret]);
  });

  it('sends logout then tears the transport down', async () => {
    const transport = new FakeTransport();
    await new EngineFacade(transport).logout();
    expect(transport.commands.map((entry) => entry.kind)).toEqual(['logout']);
    expect(transport.closed).toBe(true);
  });

  it('tears the transport down even when the logout command rejects', async () => {
    const transport = new FakeTransport();
    transport.command = () => Promise.reject(new Error('logout unimplemented'));
    await expect(new EngineFacade(transport).logout()).resolves.toBeUndefined();
    expect(transport.closed).toBe(true);
  });

  it('sends the erase and leaves the transport to the logout that follows it', async () => {
    const transport = new FakeTransport();
    await new EngineFacade(transport).forgetDevice();
    expect(transport.commands.map((entry) => entry.kind)).toEqual(['forgetDevice']);
    expect(transport.closed).toBe(false);
  });

  it('leaves no container named for the account a forget erased', async () => {
    const other = 'acct02';
    const origin = stubOrigin([
      `cipherbox-${TEST_ACCOUNT_ID}-floors`,
      `cipherbox-${TEST_ACCOUNT_ID}-staging`,
      `cipherbox-${TEST_ACCOUNT_ID}-staging-staged`,
      `cipherbox-${TEST_ACCOUNT_ID}-snapshot-cache`,
      `cipherbox-${other}-floors`,
      `cipherbox-${other}-staging`,
    ]);
    const facade = new EngineFacade(new FakeTransport(origin));

    await facade.forgetDevice();
    await facade.logout();

    expect(origin.containers.filter((name) => name.includes(TEST_ACCOUNT_ID))).toEqual([]);
    // Another account on the same profile keeps everything it named.
    expect(origin.containers.sort()).toEqual(
      [`cipherbox-${other}-floors`, `cipherbox-${other}-staging`].sort()
    );
  });

  it('erases the containers a host with its own prefix named', async () => {
    const origin = stubOrigin([
      `engine-7-${TEST_ACCOUNT_ID}-floors`,
      `engine-7-${TEST_ACCOUNT_ID}-staging`,
      `engine-7-${TEST_ACCOUNT_ID}-staging-staged`,
      `engine-7-${TEST_ACCOUNT_ID}-snapshot-cache`,
    ]);
    const facade = new EngineFacade(new FakeTransport(origin), { dbPrefix: 'engine-7' });

    await facade.forgetDevice();
    await facade.logout();

    expect(origin.containers).toEqual([]);
  });

  it('erases the containers only once the worker is torn down', async () => {
    const transport = new FakeTransport(stubOrigin([`cipherbox-${TEST_ACCOUNT_ID}-floors`]));
    const facade = new EngineFacade(transport);

    await facade.forgetDevice();
    await facade.logout();

    // An IndexedDB delete blocks while the engine holds a connection.
    expect(transport.goneAtClose).toEqual([]);
    expect(transport.closed).toBe(true);
  });

  it('erases the account the engine held when the forget landed, not after teardown', async () => {
    const origin = stubOrigin([`cipherbox-${TEST_ACCOUNT_ID}-floors`]);
    const transport = new FakeTransport(origin);
    const facade = new EngineFacade(transport);

    await facade.forgetDevice();
    // Teardown clears the session; the name the sweep needs is already latched.
    transport.account = null;
    await facade.logout();

    expect(origin.containers).toEqual([]);
  });

  it('leaves the containers of a plain logout alone', async () => {
    const origin = stubOrigin([`cipherbox-${TEST_ACCOUNT_ID}-floors`]);

    await new EngineFacade(new FakeTransport(origin)).logout();

    expect(origin.gone).toEqual([]);
  });

  /** Unlike a logout, an erase that did not land must not report success. */
  it('reports a refused erase rather than swallowing it', async () => {
    const transport = new FakeTransport();
    transport.command = () => Promise.reject(new Error('floors unreachable'));
    await expect(new EngineFacade(transport).forgetDevice()).rejects.toThrow('floors unreachable');
  });

  it('sends a create carrying no content', async () => {
    const transport = new FakeTransport();
    await new EngineFacade(transport).create(new Uint8Array(16), 'docs', 'folder');

    expect(transport.commands[0]).toEqual({
      kind: 'create',
      parent: new Uint8Array(16),
      name: 'docs',
      nodeKind: 'folder',
    });
  });

  /**
   * The engine owns the one name law. This layer must hold no copy of it: a
   * name the law refuses still reaches the engine, so a refusal is the engine's
   * verdict and never a second rule that could drift from it.
   */
  it('forwards a name the engine law refuses rather than judging it here', async () => {
    for (const name of unlawfulNames()) {
      const transport = new FakeTransport();
      const facade = new EngineFacade(transport);

      await facade.create(new Uint8Array(16), name, 'file');
      await facade.rename(new Uint8Array(16), name);

      expect(transport.commands).toEqual([
        { kind: 'create', parent: new Uint8Array(16), name, nodeKind: 'file' },
        { kind: 'rename', node: new Uint8Array(16), newName: name },
      ]);
    }
  });

  it('sends the placement, provider and retention choice as one command', async () => {
    const transport = new FakeTransport();
    const settings = byoSettings(new TextEncoder().encode('bearer-token').buffer as ArrayBuffer);

    await new EngineFacade(transport).saveVaultSettings(settings);

    expect(transport.commands[0]).toEqual({ kind: 'saveVaultSettings', settings });
  });

  it('refuses a bearer the worker would hard-reject, after every hop had copied it', async () => {
    const transport = new FakeTransport();
    const view = new TextEncoder().encode('s3cret');

    // A view is not transferable, so it would be cloned to the worker and
    // refused there — leaving a live credential in every realm on the way.
    await expect(
      new EngineFacade(transport).saveVaultSettings({
        ...byoSettings(null),
        byo: { endpoint: 'https://kubo.example', kind: 'kubo', accessToken: view as never },
      })
    ).rejects.toThrow('accessToken must be a transferable buffer');

    expect(transport.commands).toEqual([]);
    expect([...view]).toEqual(new Array(view.length).fill(0));
  });

  it('scrubs a refused bearer over its own range, not the buffer behind it', async () => {
    const backing = new ArrayBuffer(12);
    new Uint8Array(backing).fill(0xaa);
    const view = new Uint8Array(backing, 4, 6);
    view.set(new TextEncoder().encode('s3cret'));

    await expect(
      new EngineFacade(new FakeTransport()).saveVaultSettings({
        ...byoSettings(null),
        byo: { endpoint: 'https://kubo.example', kind: 'kubo', accessToken: view as never },
      })
    ).rejects.toThrow('accessToken must be a transferable buffer');

    // The bytes around the credential are the caller's, not the facade's to clear.
    const expected = new Uint8Array(backing.byteLength).fill(0xaa);
    expected.fill(0, 4, 10);
    expect([...new Uint8Array(backing)]).toEqual([...expected]);
  });

  it('scrubs a refused bearer a SharedArrayBuffer backs', async () => {
    const shared = new SharedArrayBuffer(6);
    const view = new Uint8Array(shared);
    view.set(new TextEncoder().encode('s3cret'));

    // Shared memory is not transferable, so the refusal is the only thing that
    // ever ends this credential.
    await expect(
      new EngineFacade(new FakeTransport()).saveVaultSettings({
        ...byoSettings(null),
        byo: { endpoint: 'https://kubo.example', kind: 'kubo', accessToken: view as never },
      })
    ).rejects.toThrow('accessToken must be a transferable buffer');

    expect([...view]).toEqual(new Array(view.length).fill(0));
  });

  it('streams a new file through begin/push/commit and returns the op id', async () => {
    const transport = new FakeTransport();
    const facade = new EngineFacade(transport);
    const parent = new Uint8Array(16).fill(1);

    const handle = await facade.beginWrite({ parent, name: 'a.txt' }, 5);
    expect(handle).toBe(7n);
    expect(transport.beginWrites).toEqual([{ target: { parent, name: 'a.txt' }, size: 5 }]);

    const first = new Uint8Array([1, 2, 3]).buffer;
    const second = new Uint8Array([4, 5]).buffer;
    await facade.pushChunk(handle, first);
    await facade.pushChunk(handle, second);
    expect(transport.chunks).toEqual([
      { handle: 7n, chunk: first },
      { handle: 7n, chunk: second },
    ]);

    await expect(facade.commitWrite(handle)).resolves.toBe(99n);
    expect(transport.commits).toEqual([7n]);
    // Content never rides a command: the write plane is the only path for bytes.
    expect(transport.commands).toEqual([]);
  });

  it('opens a new version of an existing node and can abandon the handle', async () => {
    const transport = new FakeTransport();
    const facade = new EngineFacade(transport);
    const node = new Uint8Array(16).fill(2);

    const handle = await facade.beginWrite({ node }, 1024);
    expect(transport.beginWrites).toEqual([{ target: { node }, size: 1024 }]);

    await facade.abortWrite(handle);
    expect(transport.aborts).toEqual([7n]);
  });

  it('carries the permission on a grant', async () => {
    const transport = new FakeTransport();
    const node = new Uint8Array(16);
    const recipient = new Uint8Array([7, 7]);
    await new EngineFacade(transport).grant(node, recipient, 'write');

    expect(transport.commands[0]).toMatchObject({
      kind: 'grant',
      permission: 'write',
      recipientIdentityPublicKey: recipient,
    });
  });

  it('spells an omitted invite deadline as a link that never expires', async () => {
    const transport = mintingTransport();
    const facade = new EngineFacade(transport);
    const node = new Uint8Array(16);

    await facade.createInviteLink(node, 'read');
    await facade.createInviteLink(node, 'write', 1_800_000_000_000n);

    expect(transport.commands[0]).toMatchObject({ kind: 'createInviteLink', expiresAt: null });
    expect(transport.commands[1]).toMatchObject({
      kind: 'createInviteLink',
      expiresAt: 1_800_000_000_000n,
    });
  });

  it('hands the minted link back to its caller', async () => {
    const minted = await new EngineFacade(mintingTransport()).createInviteLink(
      new Uint8Array(16),
      'read'
    );

    expect(minted.fragment).toBe(MINTED_FRAGMENT);
  });

  it('refuses an oversize fragment before any realm clones it', async () => {
    const transport = new FakeTransport();

    await expect(
      new EngineFacade(transport).claimInviteLink('x'.repeat(MAX_FRAGMENT_CHARS + 1))
    ).rejects.toThrow('that is not an invite link');
    expect(transport.commands).toEqual([]);
  });

  it('refuses an answer to a mint that carries no link', async () => {
    const transport = new FakeTransport();
    const facade = new EngineFacade(transport);

    await expect(facade.createInviteLink(new Uint8Array(16), 'read')).rejects.toThrow(
      'create invite link answered done'
    );
  });

  it('delegates the stream trio to the transport, window intact', async () => {
    const transport = new FakeTransport();
    const facade = new EngineFacade(transport);
    const node = new Uint8Array(16).fill(3);

    const opened = await facade.openContentStream(node);
    // The pinned size frames the media head, so the facade must hand it back
    // whole rather than only the handle it reads windows with.
    expect(opened).toEqual({ handle: 3n, size: 4096 });
    const { handle } = opened;
    const window = await facade.readStream(handle, 4096, 2);
    await facade.closeStream(handle);

    expect([...new Uint8Array(window)]).toEqual([4, 5]);
    expect(transport.opened).toEqual([node]);
    expect(transport.reads).toEqual([{ handle, offset: 4096, length: 2 }]);
    expect(transport.closedStreams).toEqual([handle]);
  });

  it('delegates snapshot and download reads to the transport', async () => {
    const transport = new FakeTransport();
    const facade = new EngineFacade(transport);
    const folder = new Uint8Array(16).fill(2);
    const node = new Uint8Array(16).fill(3);

    const view = await facade.snapshot(folder);
    expect(view.folder).toBe(folder);
    expect(transport.snapshots).toEqual([folder]);

    const content = await facade.download(node);
    expect([...new Uint8Array(content)]).toEqual([1, 2, 3]);
    expect(transport.downloads).toEqual([node]);
  });

  it('forwards a sharing read, and a null scope as the vault root', async () => {
    const transport = new FakeTransport();
    const facade = new EngineFacade(transport);
    const scope = new Uint8Array(16).fill(4);

    const view = await facade.sharing(scope);
    expect(view.scope).toBe(scope);

    await facade.sharing(null);
    expect(transport.sharingReads).toEqual([scope, null]);
  });

  it('forwards a received-shares read', async () => {
    const transport = new FakeTransport();
    const facade = new EngineFacade(transport);

    await facade.receivedShares();
    expect(transport.receivedShareReads).toBe(1);
  });

  it('reads the SIWE nonce over the transport rather than the API', async () => {
    const transport = new FakeTransport();
    const facade = new EngineFacade(transport);

    await expect(facade.siweChallenge('link')).resolves.toBe(FAKE_SIWE_NONCE);
    expect(transport.siweChallenges).toBe(1);
    expect(transport.siweChallengeIntents).toEqual(['link']);
  });

  it('forwards a bin read', async () => {
    const transport = new FakeTransport();
    const facade = new EngineFacade(transport);

    await expect(facade.bin()).resolves.toEqual(emptyBin());
    expect(transport.binReads).toBe(1);
  });

  it('forwards a vault-storage read', async () => {
    const transport = new FakeTransport();
    const facade = new EngineFacade(transport);

    await expect(facade.vaultStorage()).resolves.toEqual(emptyVaultStorage());
    expect(transport.vaultStorageReads).toBe(1);
  });

  it('forwards an auth-methods read', async () => {
    const transport = new FakeTransport();
    const facade = new EngineFacade(transport);

    await expect(facade.authMethods()).resolves.toEqual([]);
    expect(transport.authMethodReads).toBe(1);
  });

  it('sends a restore and a purge as their own commands, destination intact', async () => {
    const transport = new FakeTransport();
    const facade = new EngineFacade(transport);
    const node = new Uint8Array(16).fill(5);
    const into = new Uint8Array(16).fill(6);

    await facade.restore(node, into);
    await facade.restore(node, null);
    await facade.purge(node);

    expect(transport.commands).toEqual([
      { kind: 'restore', node, into },
      { kind: 'restore', node, into: null },
      { kind: 'purge', node },
    ]);
  });

  it('forwards a devices read', async () => {
    const transport = new FakeTransport();

    await expect(new EngineFacade(transport).devices()).resolves.toEqual([]);
    expect(transport.deviceReads).toBe(1);
  });

  it('forwards a pending-approvals read', async () => {
    const transport = new FakeTransport();

    await expect(new EngineFacade(transport).pendingApprovals()).resolves.toEqual([]);
    expect(transport.pendingApprovalReads).toBe(1);
  });

  it('names the device key a registration challenge is issued for', async () => {
    const transport = new FakeTransport();

    await expect(
      new EngineFacade(transport).deviceRegistrationChallenge('ed25519hex')
    ).resolves.toEqual(Uint8Array.of(1, 2, 3));
    expect(transport.registrationChallenges).toEqual(['ed25519hex']);
  });

  it('posts the rendezvous step it was handed, unaltered', async () => {
    const transport = new FakeTransport();
    const scalar = new Uint8Array(32).fill(5);

    await expect(
      new EngineFacade(transport).deviceRendezvous({
        kind: 'open',
        devicePublicKey: 'ed25519hex',
        scalar,
      })
    ).resolves.toEqual({ kind: 'factor', factorKey: Uint8Array.of(7, 7) });
    expect(transport.rendezvousSteps).toEqual([
      { kind: 'open', devicePublicKey: 'ed25519hex', scalar },
    ]);
  });

  it('sends a device registration carrying its label', async () => {
    const transport = new FakeTransport();

    await new EngineFacade(transport).registerDevice(
      'ed25519hex',
      'sighex',
      'token.jwt',
      'Work laptop'
    );

    expect(transport.commands).toEqual([
      {
        kind: 'registerDevice',
        publicKey: 'ed25519hex',
        signature: 'sighex',
        identityToken: 'token.jwt',
        label: 'Work laptop',
      },
    ]);
  });

  it('sends a device revoke naming only the device id', async () => {
    const transport = new FakeTransport();

    await new EngineFacade(transport).revokeDevice('7c1e-uuid');

    expect(transport.commands).toEqual([{ kind: 'revokeDevice', deviceId: '7c1e-uuid' }]);
  });

  it('sends a denial with no sealed factor on it', async () => {
    const transport = new FakeTransport();

    await new EngineFacade(transport).respondToApproval(
      'req-1',
      'deny',
      'ed25519hex',
      '02beef',
      'sighex',
      null
    );

    expect(transport.commands).toEqual([
      {
        kind: 'respondToApproval',
        requestId: 'req-1',
        decision: 'deny',
        devicePublicKey: 'ed25519hex',
        ephemeralPublicKey: '02beef',
        signature: 'sighex',
        sealedFactor: null,
      },
    ]);
  });

  it('sends a wallet link as its own command, never as a login', async () => {
    const transport = new FakeTransport();
    const signature = new Uint8Array(65).fill(7);

    await new EngineFacade(transport).siweLink('link me', signature);

    expect(transport.commands).toEqual([{ kind: 'siweLink', message: 'link me', signature }]);
  });

  it('sends an unlink naming only the method id', async () => {
    const transport = new FakeTransport();

    await new EngineFacade(transport).unlinkAuthMethod('3f2a-uuid');

    expect(transport.commands).toEqual([{ kind: 'unlinkAuthMethod', methodId: '3f2a-uuid' }]);
  });

  it('hands the caller the two public keys an import verified', async () => {
    const transport = new FakeTransport();
    const identityPublicKey = new Uint8Array(33).fill(4);
    const encPublicKey = new Uint8Array(32).fill(5);
    transport.outcome = { kind: 'contactImported', identityPublicKey, encPublicKey };

    await expect(
      new EngineFacade(transport).importContact(new Uint8Array([7, 7]))
    ).resolves.toEqual({ kind: 'contactImported', identityPublicKey, encPublicKey });
  });

  it('refuses an import the engine did not answer with a contact', async () => {
    const transport = new FakeTransport();
    transport.outcome = { kind: 'queued', opId: 3n };

    await expect(new EngineFacade(transport).importContact(new Uint8Array([7, 7]))).rejects.toThrow(
      'import contact answered queued'
    );
  });

  it('resolves a queued command with the op id its events will repeat', async () => {
    const transport = new FakeTransport();
    transport.outcome = { kind: 'queued', opId: 11n };

    await expect(new EngineFacade(transport).delete(new Uint8Array(16))).resolves.toEqual({
      kind: 'queued',
      opId: 11n,
    });
  });

  it('delegates event subscription to the transport', () => {
    const transport = new FakeTransport();
    const facade = new EngineFacade(transport);
    const unsubscribe = facade.subscribe(() => undefined);
    expect(transport.listeners).toHaveLength(1);
    unsubscribe();
    expect(transport.listeners).toHaveLength(0);
  });
});
