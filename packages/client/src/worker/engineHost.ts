/**
 * The engine host: wraps the wasm-bindgen `EngineHandle` in the wire-protocol
 * shape the worker serves. Runs inside the engine worker realm; key material
 * never leaves it.
 */

import type {
  CommandDescriptor,
  EventDescriptor,
  SnapshotDescriptor,
  WriteHandle,
  WriteTarget,
} from './protocol.js';
import type { EngineWasm } from './engineWasm.js';
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
  pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void>;
  /** Closes the handle and journals its op; resolves with the durable op id. */
  commitWrite(handle: WriteHandle): Promise<bigint>;
  abortWrite(handle: WriteHandle): Promise<void>;
  /** Reads `folder`, or the engine's own root when `folder` is `null`. */
  snapshot(folder: Uint8Array | null): Promise<SnapshotDescriptor>;
  download(node: Uint8Array): Promise<ArrayBuffer>;
  nextEvent(): Promise<EventDescriptor | null>;
}

export class EngineHost implements EngineHostLike {
  private readonly handle;

  constructor(
    private readonly wasm: EngineWasm,
    seams: unknown,
    profile?: string,
    storageHeadroomBytes?: number
  ) {
    this.handle = new wasm.EngineHandle(
      seams,
      profile,
      undefined,
      undefined,
      undefined,
      undefined,
      storageHeadroomBytes
    );
  }

  async start(secret: ArrayBuffer): Promise<void> {
    // The engine copies the secret into its `Zeroizing` store; scrub the
    // worker's transferred copy immediately after so no plaintext lingers.
    const view = new Uint8Array(secret);
    try {
      await this.handle.start(view);
    } finally {
      view.fill(0);
    }
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

  async pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void> {
    // The handle copies into WASM memory synchronously; a view over the
    // transferred buffer is safe here.
    await this.handle.pushChunk(handle, new Uint8Array(chunk));
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

  async download(node: Uint8Array): Promise<ArrayBuffer> {
    const bytes = await this.handle.download(this.wasm.NodeId.fromBytes(node));
    // The handle returns a JS-owned copy (never a WASM-memory view); reuse its
    // exact backing buffer for the transfer, re-slicing only a partial view.
    return bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
      ? (bytes.buffer as ArrayBuffer)
      : (bytes.slice().buffer as ArrayBuffer);
  }

  async nextEvent(): Promise<EventDescriptor | null> {
    const event = await this.handle.nextEvent();
    return event ? readEvent(this.wasm, event) : null;
  }
}
