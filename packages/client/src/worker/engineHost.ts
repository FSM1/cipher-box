/**
 * The engine host: wraps the wasm-bindgen `EngineHandle` in the wire-protocol
 * shape the worker serves. Runs inside the engine worker realm; key material
 * never leaves it.
 */

import type {
  CommandDescriptor,
  EventDescriptor,
  SnapshotDescriptor,
  StreamHandle,
  WriteHandle,
  WriteTarget,
} from './protocol.js';
import type { EngineWasm } from './engineWasm.js';
import type { EngineHostConfig } from '../spawnEngineWorker.js';
import { buildCommand, readEvent, readSnapshot } from './commandCodec.js';

/**
 * The engine-facing surface the protocol server ([`serveEngine`]) drives. The
 * real [`EngineHost`] wraps WASM; the browser suite substitutes a fake to
 * exercise transport ordering and out-of-order correlation deterministically.
 */
export interface EngineHostLike {
  start(secret: ArrayBuffer): Promise<void>;
  command(command: CommandDescriptor): Promise<void>;
  /** Opens a write handle for `size` plaintext bytes; the engine reserves them. */
  beginWrite(target: WriteTarget, size: number): Promise<WriteHandle>;
  /** Takes ownership of `chunk`: the host scrubs the plaintext once it lands. */
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
      // The accelerator bearer is a session credential, never a build-time
      // constant, so no browser config surface supplies one yet.
      undefined,
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

  start(secret: ArrayBuffer): Promise<void> {
    return this.scrubbing(secret, (view) => this.handle.start(view));
  }

  async command(command: CommandDescriptor): Promise<void> {
    await this.handle.command(buildCommand(this.wasm, command));
  }

  beginWrite(target: WriteTarget, size: number): Promise<WriteHandle> {
    if ('node' in target) {
      return this.handle.beginWrite(
        undefined,
        undefined,
        this.wasm.NodeId.fromBytes(target.node),
        size
      );
    }
    return this.handle.beginWrite(
      this.wasm.NodeId.fromBytes(target.parent),
      target.name,
      undefined,
      size
    );
  }

  pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void> {
    return this.scrubbing(chunk, (view) => this.handle.pushChunk(handle, view));
  }

  commitWrite(handle: WriteHandle): Promise<bigint> {
    return this.handle.commitWrite(handle);
  }

  async abortWrite(handle: WriteHandle): Promise<void> {
    await this.handle.abortWrite(handle);
  }

  async snapshot(folder: Uint8Array | null): Promise<SnapshotDescriptor> {
    const view = await this.handle.snapshot(
      folder === null ? undefined : this.wasm.NodeId.fromBytes(folder)
    );
    return readSnapshot(this.wasm, view);
  }

  siweChallenge(): Promise<string> {
    return this.handle.siweChallenge();
  }

  async download(node: Uint8Array): Promise<ArrayBuffer> {
    return ownedBuffer(await this.handle.download(this.wasm.NodeId.fromBytes(node)));
  }

  openContentStream(node: Uint8Array): Promise<StreamHandle> {
    return this.handle.openContentStream(this.wasm.NodeId.fromBytes(node));
  }

  async readStream(handle: StreamHandle, offset: number, length: number): Promise<ArrayBuffer> {
    return ownedBuffer(await this.handle.readStream(handle, offset, length));
  }

  async closeStream(handle: StreamHandle): Promise<void> {
    await this.handle.closeStream(handle);
  }

  async nextEvent(): Promise<EventDescriptor | null> {
    const event = await this.handle.nextEvent();
    return event ? readEvent(this.wasm, event) : null;
  }
}
