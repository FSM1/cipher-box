/**
 * The engine host: wraps the wasm-bindgen `EngineHandle` in the wire-protocol
 * shape the worker serves. Runs inside the engine worker realm; key material
 * never leaves it.
 */

import { wipeTransfer } from '../buffers.js';
import { commandTransfer } from './protocol.js';
import type {
  AuthMethodDescriptor,
  CommandDescriptor,
  CommandOutcomeDescriptor,
  EventDescriptor,
  ReceivedShareDescriptor,
  SharingDescriptor,
  SnapshotDescriptor,
  OpenedStream,
  StreamHandle,
  VaultStorageDescriptor,
  WriteHandle,
  WriteTarget,
} from './protocol.js';
import type { EngineWasm, WasmCommandOutcome, WasmEngineHandle } from './engineWasm.js';
import type { EngineHostConfig } from '../spawnEngineWorker.js';
import {
  buffer,
  buildCommand,
  count,
  minted,
  nodeId,
  permissionFrom,
  readAuthMethods,
  readEvent,
  readReceivedShare,
  readSharing,
  readSnapshot,
  readVaultStorage,
  record,
  text,
} from './commandCodec.js';

/**
 * The engine-facing surface the protocol server ([`serveEngine`]) drives. The
 * real [`EngineHost`] wraps WASM; the browser suite substitutes a fake to
 * exercise transport ordering and out-of-order correlation deterministically.
 */
export interface EngineHostLike {
  /** Cold-starts the engine for `accountId`, whose durable state it opens. */
  start(secret: ArrayBuffer, accountId: string): Promise<void>;
  /** Runs one command; resolves with what it produced. */
  command(command: CommandDescriptor): Promise<CommandOutcomeDescriptor>;
  /** Opens a write handle for `size` plaintext bytes; the engine reserves them. */
  beginWrite(target: WriteTarget, size: number): Promise<WriteHandle>;
  /** Takes ownership of `chunk`: the host is its terminal owner, so it scrubs the
   * plaintext to bound the lifetime of a copy no caller can reach. */
  pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void>;
  /** Closes the handle and journals its op; resolves with the durable op id. */
  commitWrite(handle: WriteHandle): Promise<bigint>;
  abortWrite(handle: WriteHandle): Promise<void>;
  snapshot(folder: Uint8Array | null): Promise<SnapshotDescriptor>;
  /** Reads the contact book and `scope`'s committed grants, or the root's. */
  sharing(scope: Uint8Array | null): Promise<SharingDescriptor>;
  /** Reads this vault's accepted shares and the engine's verdict on each. */
  receivedShares(): Promise<ReceivedShareDescriptor[]>;
  vaultStorage(): Promise<VaultStorageDescriptor>;
  authMethods(): Promise<AuthMethodDescriptor[]>;
  siweChallenge(): Promise<string>;
  download(node: Uint8Array): Promise<ArrayBuffer>;
  /**
   * Opens a read stream pinned to the node's current head content version,
   * reporting that version's plaintext size with the handle.
   */
  openContentStream(node: Uint8Array): Promise<OpenedStream>;
  readStream(handle: StreamHandle, offset: number, length: number): Promise<ArrayBuffer>;
  closeStream(handle: StreamHandle): Promise<void>;
  nextEvent(): Promise<EventDescriptor | null>;
}

/**
 * The handle returns a JS-owned copy (never a WASM-memory view); reuse its exact
 * backing buffer for the transfer, re-slicing only a partial view.
 */
function ownedBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
    ? (bytes.buffer as ArrayBuffer)
    : (bytes.slice().buffer as ArrayBuffer);
}

/** A getter the outcome's own `kind` promises, refused when it answers nothing. */
function present<T>(value: T | undefined, kind: string, field: string): T {
  if (value === undefined) throw new Error(`command outcome ${kind} carries no ${field}`);
  return value;
}

/** Reads a wasm-bindgen `CommandOutcome`'s getters into a descriptor. */
function readOutcome(wasm: EngineWasm, outcome: WasmCommandOutcome): CommandOutcomeDescriptor {
  const kind = outcome.kind;
  switch (kind) {
    case 'done':
      return { kind: 'done' };
    case 'queued':
      return { kind: 'queued', opId: present(outcome.opId, kind, 'opId') };
    case 'contactImported':
      return {
        kind: 'contactImported',
        identityPublicKey: present(outcome.identityPublicKey, kind, 'identityPublicKey'),
        encPublicKey: present(outcome.encPublicKey, kind, 'encPublicKey'),
      };
    case 'inviteLinkMinted':
      return { kind: 'inviteLinkMinted', fragment: present(outcome.fragment, kind, 'fragment') };
    case 'shareAccepted':
      return {
        kind: 'shareAccepted',
        scopeId: present(outcome.scopeId, kind, 'scopeId'),
        sequence: present(outcome.sequence, kind, 'sequence'),
        permission: permissionFrom(wasm, present(outcome.permission, kind, 'permission')),
        newlyAdded: present(outcome.newlyAdded, kind, 'newlyAdded'),
      };
  }
  throw new Error(`unknown command outcome ${kind}`);
}

/** A refusal carrying one of the engine's own stable codes, as the engine does. */
function refuse(code: 'notStarted' | 'alreadyStarted', message: string): Error {
  return Object.assign(new Error(message), { code });
}

/** What the engine instance itself is configured with, beyond its seams. */
export type EngineHostOptions = Pick<
  EngineHostConfig,
  'apiBaseUrl' | 'acceleratorBaseUrl' | 'publicGateways' | 'profile'
> & {
  /** Origin headroom the engine splits into its staging budget. */
  storageHeadroomBytes?: number;
};

export class EngineHost implements EngineHostLike {
  private engine: { handle: WasmEngineHandle; accountId: string } | null = null;
  private live!: (handle: WasmEngineHandle) => void;
  /** Resolves with the engine once one exists, so the event pump can wait. */
  private readonly running = new Promise<WasmEngineHandle>((resolve) => {
    this.live = resolve;
  });

  constructor(
    private readonly wasm: EngineWasm,
    private readonly seams: (accountId: string) => unknown,
    private readonly options: EngineHostOptions
  ) {}

  /**
   * The engine for `accountId`, built by the first `start`. Construction waits
   * for that call because the seams are namespaced per account, and no account
   * is known until the login secret arrives.
   */
  private engineFor(accountId: string): WasmEngineHandle {
    const id = text(accountId, 'accountId');
    const current = this.engine;
    if (current) {
      if (current.accountId !== id)
        throw refuse('alreadyStarted', 'another account holds this engine');
      return current.handle;
    }
    const handle = new this.wasm.EngineHandle(
      this.seams(id),
      this.options.profile,
      this.options.apiBaseUrl,
      this.options.acceleratorBaseUrl,
      this.options.publicGateways,
      this.options.storageHeadroomBytes
    );
    this.engine = { handle, accountId: id };
    this.live(handle);
    return handle;
  }

  /** The running engine; refused before `start`, as the engine itself refuses. */
  private get handle(): WasmEngineHandle {
    if (!this.engine) throw refuse('notStarted', 'engine not started');
    return this.engine.handle;
  }

  /**
   * Runs `use` over `buffer`, scrubbing it once the call settles — including
   * when it rejects. Buffers reaching the host arrive by transfer, making the
   * worker their terminal owner, and the engine below copies what it keeps.
   */
  private async scrubbing(
    buffer: ArrayBuffer,
    use: (view: Uint8Array) => Promise<unknown>
  ): Promise<void> {
    const view = new Uint8Array(buffer);
    try {
      await use(view);
    } finally {
      view.fill(0);
    }
  }

  async start(secret: ArrayBuffer, accountId: string): Promise<void> {
    // Inside `scrubbing`: a refused account still leaves this frame the
    // secret's terminal owner (security rule 7).
    return this.scrubbing(buffer(secret, 'secret'), (view) =>
      this.engineFor(accountId).start(view)
    );
  }

  async command(command: CommandDescriptor): Promise<CommandOutcomeDescriptor> {
    // A buffer the descriptor carries arrived transferred, so this realm holds
    // the only copy — including on the routes that refuse before the codec is
    // reached, which is where the codec's own scrub cannot run.
    try {
      const outcome = await this.handle.command(buildCommand(this.wasm, command));
      try {
        return readOutcome(this.wasm, outcome);
      } finally {
        outcome.free();
      }
    } finally {
      wipeTransfer(commandTransfer(command));
    }
  }

  async beginWrite(target: WriteTarget, size: number): Promise<WriteHandle> {
    const reserved = count(size, 'size');
    const fields = record(target, 'target');
    if ('node' in fields) {
      return this.handle.beginWrite(
        undefined,
        undefined,
        nodeId(this.wasm, fields.node, 'node'),
        reserved
      );
    }
    return this.handle.beginWrite(
      nodeId(this.wasm, fields.parent, 'parent'),
      text(fields.name, 'name'),
      undefined,
      reserved
    );
  }

  async pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void> {
    const write = minted(handle, 'handle');
    return this.scrubbing(buffer(chunk, 'chunk'), (view) => this.handle.pushChunk(write, view));
  }

  async commitWrite(handle: WriteHandle): Promise<bigint> {
    return this.handle.commitWrite(minted(handle, 'handle'));
  }

  async abortWrite(handle: WriteHandle): Promise<void> {
    await this.handle.abortWrite(minted(handle, 'handle'));
  }

  async snapshot(folder: Uint8Array | null): Promise<SnapshotDescriptor> {
    const view = await this.handle.snapshot(
      folder === null ? undefined : nodeId(this.wasm, folder, 'folder')
    );
    return readSnapshot(this.wasm, view);
  }

  async sharing(scope: Uint8Array | null): Promise<SharingDescriptor> {
    const view = await this.handle.sharing(
      scope === null ? undefined : nodeId(this.wasm, scope, 'scope')
    );
    return readSharing(this.wasm, view);
  }

  async receivedShares(): Promise<ReceivedShareDescriptor[]> {
    const rows = await this.handle.receivedShares();
    return rows.map((row) => readReceivedShare(this.wasm, row));
  }

  async vaultStorage(): Promise<VaultStorageDescriptor> {
    return readVaultStorage(this.wasm, await this.handle.vaultStorage());
  }

  async authMethods(): Promise<AuthMethodDescriptor[]> {
    return readAuthMethods(this.wasm, await this.handle.authMethods());
  }

  siweChallenge(): Promise<string> {
    return this.handle.siweChallenge();
  }

  async download(node: Uint8Array): Promise<ArrayBuffer> {
    return ownedBuffer(await this.handle.download(nodeId(this.wasm, node, 'node')));
  }

  async openContentStream(node: Uint8Array): Promise<OpenedStream> {
    // A wasm-bindgen class instance is not structured-cloneable, so the getters
    // are read into a plain record before it can reach `postMessage`.
    const opened = await this.handle.openContentStream(nodeId(this.wasm, node, 'node'));
    return { handle: opened.handle, size: opened.size };
  }

  async readStream(handle: StreamHandle, offset: number, length: number): Promise<ArrayBuffer> {
    return ownedBuffer(
      await this.handle.readStream(
        minted(handle, 'handle'),
        count(offset, 'offset'),
        count(length, 'length')
      )
    );
  }

  async closeStream(handle: StreamHandle): Promise<void> {
    await this.handle.closeStream(minted(handle, 'handle'));
  }

  async nextEvent(): Promise<EventDescriptor | null> {
    const handle = await this.running;
    const event = await handle.nextEvent();
    return event ? readEvent(this.wasm, event) : null;
  }
}
