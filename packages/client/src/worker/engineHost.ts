/**
 * The engine host: wraps the wasm-bindgen `EngineHandle` in the wire-protocol
 * shape the worker serves. Runs inside the engine worker realm; key material
 * never leaves it.
 */

import { wipeTransfer } from '../buffers.js';
import { commandTransfer, wipeRendezvousSecrets } from './protocol.js';
import type {
  CommandDescriptor,
  CommandOutcomeDescriptor,
  EventDescriptor,
  OpenedStream,
  ReadAnswer,
  ReadDescriptor,
  ReadResult,
  ReadResultValue,
  StreamHandle,
  WriteHandle,
  WriteTarget,
} from './protocol.js';
import type { EngineWasm, WasmEngineHandle } from './engineWasm.js';
import type { EngineHostConfig } from '../spawnEngineWorker.js';
import {
  buffer,
  count,
  minted,
  nodeId,
  readAuthMethods,
  readBin,
  readEvent,
  readInvitePreview,
  readRendezvous,
  readReceivedShares,
  readSharing,
  readSnapshot,
  readVaultStorage,
  text,
} from './commandCodec.js';

/**
 * The engine-facing surface the protocol server ([`serveEngine`]) drives. The
 * real [`EngineHost`] wraps WASM; the browser suite substitutes a fake to
 * exercise transport ordering and out-of-order correlation deterministically.
 */
export interface EngineHostLike {
  /**
   * Cold-starts the engine for `accountId`, whose durable state it opens. The
   * login presents `identityToken` when the start follows an exchange.
   */
  start(secret: ArrayBuffer, accountId: string, identityToken?: string): Promise<void>;
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
  /** Serves one read, resolving with what that kind answers ([`ReadResult`]). */
  read<D extends ReadDescriptor>(read: D): Promise<ReadResult<D>>;
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

/**
 * The check each answer whose enum values this build must know passes before
 * it leaves the worker. An answer with no enum value needs none.
 */
const ANSWER_CHECKS: {
  [K in ReadAnswer['kind']]?: (value: Extract<ReadAnswer, { kind: K }>['value']) => unknown;
} = {
  snapshot: readSnapshot,
  sharing: readSharing,
  receivedShares: readReceivedShares,
  invitePreview: readInvitePreview,
  bin: readBin,
  vaultStorage: readVaultStorage,
  authMethods: readAuthMethods,
  deviceRendezvous: readRendezvous,
};

/** The answer's value, checked, with plaintext bytes as a transferable buffer. */
function crossed(answer: ReadAnswer): ReadResultValue {
  (ANSWER_CHECKS[answer.kind] as ((value: unknown) => unknown) | undefined)?.(answer.value);
  return answer.value instanceof Uint8Array ? ownedBuffer(answer.value) : answer.value;
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

  async start(secret: ArrayBuffer, accountId: string, identityToken?: string): Promise<void> {
    // Inside `scrubbing`: a refused account still leaves this frame the
    // secret's terminal owner (security rule 7).
    return this.scrubbing(buffer(secret, 'secret'), (view) =>
      this.engineFor(accountId).start(view, identityToken)
    );
  }

  async command(command: CommandDescriptor): Promise<CommandOutcomeDescriptor> {
    // A buffer the descriptor carries arrived transferred, so this realm holds
    // the only copy. The engine copies what it keeps before `command` returns,
    // so this frame, the terminal owner, scrubs it then rather than when the
    // command settles.
    let answer: Promise<CommandOutcomeDescriptor>;
    try {
      answer = this.handle.command(command);
    } finally {
      wipeTransfer(commandTransfer(command));
    }
    return await answer;
  }

  async beginWrite(target: WriteTarget, size: number): Promise<WriteHandle> {
    return this.handle.beginWrite(target, count(size, 'size'));
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

  /**
   * Hands the read to the engine, or before a start to the reads that need no
   * session. The engine decodes the descriptor before the call returns, so
   * this frame, the last owner of what it carried (AGENTS.md 7), scrubs it then.
   */
  async read<D extends ReadDescriptor>(read: D): Promise<ReadResult<D>> {
    let answer: Promise<ReadAnswer>;
    try {
      answer = this.engine ? this.engine.handle.read(read) : this.wasm.readUnstarted(read);
    } finally {
      wipeRendezvousSecrets((read as { step?: unknown }).step);
    }
    return crossed(await answer) as ReadResult<D>;
  }

  async openContentStream(node: Uint8Array): Promise<OpenedStream> {
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
    const handle = await this.running;
    const event = await handle.nextEvent();
    return event ? readEvent(event) : null;
  }
}
