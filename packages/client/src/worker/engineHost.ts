/**
 * The engine host: wraps the wasm-bindgen `EngineHandle` in the wire-protocol
 * shape the worker serves. Runs inside the engine worker realm; key material
 * never leaves it.
 */

import type {
  CommandDescriptor,
  CommandOutcomeDescriptor,
  EventDescriptor,
  SnapshotDescriptor,
  StreamHandle,
  WriteHandle,
  WriteTarget,
} from './protocol.js';
import type { EngineWasm, WasmCommandOutcome } from './engineWasm.js';
import type { EngineHostConfig } from '../spawnEngineWorker.js';
import {
  buffer,
  buildCommand,
  count,
  minted,
  nodeId,
  readEvent,
  readSnapshot,
  record,
  text,
} from './commandCodec.js';

/**
 * The engine-facing surface the protocol server ([`serveEngine`]) drives. The
 * real [`EngineHost`] wraps WASM; the browser suite substitutes a fake to
 * exercise transport ordering and out-of-order correlation deterministically.
 */
export interface EngineHostLike {
  start(secret: ArrayBuffer): Promise<void>;
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
  siweChallenge(): Promise<string>;
  download(node: Uint8Array): Promise<ArrayBuffer>;
  /** Opens a read stream pinned to the node's current head content version. */
  openContentStream(node: Uint8Array): Promise<StreamHandle>;
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

/**
 * A getter the outcome's own `kind` promises, refused when it answers nothing.
 * A build whose engine and glue disagree must fail the call rather than ship a
 * descriptor missing the field its variant is defined by.
 */
function present<T>(value: T | undefined, kind: string, field: string): T {
  if (value === undefined) throw new Error(`command outcome ${kind} carries no ${field}`);
  return value;
}

/** Reads a wasm-bindgen `CommandOutcome`'s getters into a descriptor. */
function readOutcome(outcome: WasmCommandOutcome): CommandOutcomeDescriptor {
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
  }
  throw new Error(`unknown command outcome ${kind}`);
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
  private readonly handle;

  constructor(
    private readonly wasm: EngineWasm,
    seams: unknown,
    options: EngineHostOptions
  ) {
    this.handle = new wasm.EngineHandle(
      seams,
      options.profile,
      options.apiBaseUrl,
      options.acceleratorBaseUrl,
      options.publicGateways,
      options.storageHeadroomBytes
    );
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

  async start(secret: ArrayBuffer): Promise<void> {
    return this.scrubbing(buffer(secret, 'secret'), (view) => this.handle.start(view));
  }

  async command(command: CommandDescriptor): Promise<CommandOutcomeDescriptor> {
    const outcome = await this.handle.command(buildCommand(this.wasm, command));
    try {
      return readOutcome(outcome);
    } finally {
      outcome.free();
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

  siweChallenge(): Promise<string> {
    return this.handle.siweChallenge();
  }

  async download(node: Uint8Array): Promise<ArrayBuffer> {
    return ownedBuffer(await this.handle.download(nodeId(this.wasm, node, 'node')));
  }

  async openContentStream(node: Uint8Array): Promise<StreamHandle> {
    return this.handle.openContentStream(nodeId(this.wasm, node, 'node'));
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
    const event = await this.handle.nextEvent();
    return event ? readEvent(this.wasm, event) : null;
  }
}
