/**
 * The leader-side broadcast relay (blueprint/web-client.md "Engine hosting and
 * tab leadership"). The leader owns the single engine worker over its
 * `LocalTransport`; this relay bridges that worker to follower tabs over the
 * `BroadcastChannel`:
 *
 * - follower command → the leader's worker → correlated response back;
 * - every engine event → fanned out to all followers in emission order;
 * - each tab's open folder → the leader's **focus-window union**, so freshness
 *   follows whichever tab is focused (the RefreshHintSource seam, cross-tab).
 *
 * Nothing the leader sends on the channel carries plaintext: only key-free
 * `EventDescriptor`s and command/write acks. Read and ranged-read results go to
 * the private `PortCourier` port that follower dialed, one per follower per
 * leadership. The follower→leader direction is unchanged and still broadcasts
 * command arguments and upload chunks.
 */

import type {
  BroadcastChannelLike,
  FollowerMessage,
  LeaderMessage,
  ReadPortRequest,
  ReadPortResponse,
  WireRead,
  WireStream,
} from './broadcast.js';
import { EngineRequestError } from './correlatedTransport.js';
import type { MessagePortLike, PortCourier } from './portRelay.js';
import type { EngineTransport } from './transport.js';
import type { SnapshotDescriptor, StreamHandle, WriteHandle } from './worker/protocol.js';
import { WriteQueue } from './writeQueue.js';

/** The correlated ack envelope addressing one follower request. */
type Ack = { type: 'cb:response'; token: string; clientId: string; requestId: number };

/** One follower's read port, with the listener bound to it. */
interface ReadPortEntry {
  readonly port: MessagePortLike;
  readonly listener: (event: MessageEvent) => void;
  clientId: string | null;
  /** Reclaims a port that never named itself, so an unnamed one cannot pile up. */
  readonly naming: ReturnType<typeof setTimeout>;
}

export interface LeaderRelayOptions {
  /** How long a freshly dialed port has to name the follower behind it. */
  namingTimeoutMs?: number;
}

const DEFAULT_NAMING_TIMEOUT_MS = 5000;

/** Which handle table a step addresses. */
type HandleKind = 'write' | 'stream';

/**
 * Refuses a step on a handle the asking tab does not own. Handle ids are one
 * global namespace across tabs, so the refusal is spelled exactly like the
 * engine's own unknown-handle error: a probing tab learns nothing a legitimate
 * one would not.
 */
function unknownHandle(kind: HandleKind): EngineRequestError {
  return new EngineRequestError(
    `unknown ${kind} handle`,
    kind === 'write' ? 'unknownWriteHandle' : 'unknownStreamHandle'
  );
}

/** Projects a caught failure onto the wire's `error`/`code` fields. */
function wireError(error: unknown): { error: string; code?: string } {
  return {
    error: error instanceof Error ? error.message : String(error),
    code: error instanceof EngineRequestError ? error.code : undefined,
  };
}

/**
 * Tracks each tab's open folder and derives the union — the set of distinct
 * folders any tab has open. Nodes are compared by their bytes (hex-keyed).
 */
class FocusRegistry {
  private readonly perClient = new Map<string, string | null>();
  private union = new Set<string>();

  /** Records a client's focus; returns whether the union changed. */
  set(clientId: string, node: Uint8Array | null): boolean {
    this.perClient.set(clientId, node ? hex(node) : null);
    return this.recomputeUnion();
  }

  /** Drops a departed client; returns whether the union changed. */
  remove(clientId: string): boolean {
    if (!this.perClient.delete(clientId)) return false;
    return this.recomputeUnion();
  }

  /** The current union as a stable, sorted list of hex node ids. */
  snapshot(): string[] {
    return [...this.union].sort();
  }

  private recomputeUnion(): boolean {
    const next = new Set<string>();
    for (const node of this.perClient.values()) if (node) next.add(node);
    if (next.size === this.union.size && [...next].every((n) => this.union.has(n))) return false;
    this.union = next;
    return true;
  }
}

function hex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export class LeaderRelay {
  private readonly focus = new FocusRegistry();
  private readonly writes = new WriteQueue();
  // Which client opened each open handle. Handle ids are one global namespace
  // across tabs, so this binds every step to the tab that owns the upload — and
  // lets a departing tab's handles be released.
  private readonly writeOwners = new Map<WriteHandle, string>();
  // Same binding for read streams: a handle is a capability, and a stream left
  // open pins a content version (and its key) in the leader's engine.
  private readonly streamOwners = new Map<StreamHandle, string>();
  // Clients that left while one of their handles was still being minted. The
  // mint completes after an await, so without this the release sweep runs
  // against a map the handle has not landed in yet and the handle is stranded.
  // An entry lives only as long as the mints it guards: one that outlived them
  // would refuse every later handle from a tab that is in fact still running.
  private readonly departed = new Set<string>();
  private readonly mintsInFlight = new Map<string, number>();
  private readonly readPorts = new Set<ReadPortEntry>();
  private readonly namingTimeoutMs: number;
  private readonly unsubscribe: () => void;
  private readonly unsubscribePorts: () => void;
  private closed = false;
  // An unguessable per-leadership capability. It stamps every leader→follower
  // message so followers reject forged acks/events from a non-leader same-origin
  // context (integrity defense-in-depth; same-origin is the trust boundary).
  private readonly token = globalThis.crypto.randomUUID();
  private readonly onMessage = (event: MessageEvent): void => this.receive(event.data);

  constructor(
    private readonly channel: BroadcastChannelLike,
    private readonly transport: EngineTransport,
    private readonly courier: PortCourier,
    options: LeaderRelayOptions = {}
  ) {
    this.namingTimeoutMs = options.namingTimeoutMs ?? DEFAULT_NAMING_TIMEOUT_MS;
    this.channel.addEventListener('message', this.onMessage);
    this.unsubscribePorts = this.courier.onPort((port) => this.adoptPort(port));
    this.unsubscribe = this.transport.subscribe((event) => {
      this.post({ type: 'cb:event', token: this.token, event });
    });
    // Announce leadership so followers (existing or newly-elected-away) reconnect.
    this.post({ type: 'cb:leader', token: this.token });
  }

  /** Folds the leader tab's own open folder into the focus-window union. */
  reportLocalFocus(clientId: string, node: Uint8Array | null): void {
    if (this.closed) return;
    if (this.focus.set(clientId, node)) this.refreshHint();
  }

  close(): void {
    if (this.closed) return;
    // Announce the graceful step-down before latching closed so followers re-arm
    // their readiness gate and reject in-flight work instead of hanging on a
    // leader that is gone. A crashed leader can't send this; the next leader's
    // fresh token covers that path.
    this.post({ type: 'cb:leaderGone', token: this.token });
    // Detach before latching: `postPort` drops messages once closed, so the
    // `cb:portClosed` notice has to go out while the relay is still open.
    this.unsubscribePorts();
    for (const entry of [...this.readPorts]) this.detachPort(entry);
    this.closed = true;
    this.releaseHandles(null);
    this.unsubscribe();
    this.channel.removeEventListener('message', this.onMessage);
  }

  private receive(message: FollowerMessage | { type?: string }): void {
    if (this.closed) return;
    switch (message.type) {
      case 'cb:hello':
        this.departed.delete((message as Extract<FollowerMessage, { type: 'cb:hello' }>).clientId);
        this.post({ type: 'cb:leader', token: this.token });
        return;
      case 'cb:command':
        void this.forward(message as Extract<FollowerMessage, { type: 'cb:command' }>);
        return;
      case 'cb:portWanted':
        void this.announceHost();
        return;
      case 'cb:write':
        this.serveWrite(message as Extract<FollowerMessage, { type: 'cb:write' }>);
        return;
      case 'cb:focus': {
        const { clientId, node } = message as Extract<FollowerMessage, { type: 'cb:focus' }>;
        if (this.focus.set(clientId, node)) this.refreshHint();
        return;
      }
      case 'cb:bye': {
        const { clientId } = message as Extract<FollowerMessage, { type: 'cb:bye' }>;
        if (this.focus.remove(clientId)) this.refreshHint();
        // Only a mint the sweep below cannot see needs guarding.
        if (this.mintsInFlight.has(clientId)) this.departed.add(clientId);
        this.releaseHandles(clientId);
        this.detachPortOf(clientId);
        return;
      }
    }
  }

  private async forward(message: Extract<FollowerMessage, { type: 'cb:command' }>): Promise<void> {
    const { clientId, requestId, command } = message;
    try {
      await this.transport.command(command, []);
      this.post({ type: 'cb:response', token: this.token, clientId, requestId, ok: true });
    } catch (error) {
      this.post({
        type: 'cb:response',
        token: this.token,
        clientId,
        requestId,
        ok: false,
        ...wireError(error),
      });
    }
  }

  /**
   * Publishes where this leadership takes read ports. A follower dials it rather
   * than publishing an address of its own, so no context can push a port at a
   * tab that never asked for one. Silent without a broker: the asking follower's
   * read then fails closed on its own gate.
   */
  private async announceHost(): Promise<void> {
    try {
      const address = await this.courier.address();
      this.post({ type: 'cb:portHost', token: this.token, address });
    } catch {
      return;
    }
  }

  private adoptPort(port: MessagePortLike): void {
    if (this.closed) {
      port.close();
      return;
    }
    const entry: ReadPortEntry = {
      port,
      clientId: null,
      listener: (event) => this.onPortMessage(entry, event.data),
      naming: setTimeout(() => this.detachPort(entry), this.namingTimeoutMs),
    };
    port.addEventListener('message', entry.listener);
    port.start?.();
    this.readPorts.add(entry);
  }

  /** A same-origin port is untrusted input: anything off-shape is dropped. */
  private onPortMessage(entry: ReadPortEntry, data: unknown): void {
    if (this.closed) return;
    const message = data as ReadPortRequest | { type?: unknown };
    if (message.type === 'cb:portHello') {
      const { clientId } = message as Extract<ReadPortRequest, { type: 'cb:portHello' }>;
      if (entry.clientId !== null || typeof clientId !== 'string') return;
      // A re-brokering follower supersedes the port it held before, and by
      // greeting proves it outlived whatever `cb:bye` marked it departed.
      this.detachPortOf(clientId);
      this.departed.delete(clientId);
      clearTimeout(entry.naming);
      entry.clientId = clientId;
      this.postPort(entry.port, { type: 'cb:portReady', token: this.token });
      return;
    }
    // A port serves reads only once named — that name is how `cb:bye` reclaims it,
    // and how a stream step is bound to the tab that owns the handle.
    const clientId = entry.clientId;
    if (clientId === null) return;
    const requestId = (message as { requestId?: unknown }).requestId;
    if (typeof requestId !== 'number') return;
    if (message.type === 'cb:portRead') {
      const { read } = message as Extract<ReadPortRequest, { type: 'cb:portRead' }>;
      void this.answerPort(entry, requestId, () => this.readValue(read));
      return;
    }
    if (message.type !== 'cb:portStream') return;
    const { stream } = message as Extract<ReadPortRequest, { type: 'cb:portStream' }>;
    void this.answerPort(entry, requestId, () => this.streamStep(clientId, stream));
  }

  /** Runs one port-borne step and posts its correlated result down that port. */
  private async answerPort(
    entry: ReadPortEntry,
    requestId: number,
    step: () => Promise<SnapshotDescriptor | ArrayBuffer | string | StreamHandle | undefined>
  ): Promise<void> {
    try {
      const result = await step();
      if (this.closed || !this.readPorts.has(entry)) {
        // The port went away while the read ran, so nobody will receive this
        // window: wipe it rather than leave plaintext for the collector
        // (AGENTS.md 7 — with no transfer to make, this frame is its last owner).
        if (result instanceof ArrayBuffer) new Uint8Array(result).fill(0);
        return;
      }
      // Transferred, not cloned: the plaintext leaves this tab's heap outright.
      this.postPort(
        entry.port,
        { type: 'cb:portResult', requestId, ok: true, result },
        result instanceof ArrayBuffer ? [result] : undefined
      );
    } catch (error) {
      this.postPort(entry.port, {
        type: 'cb:portResult',
        requestId,
        ok: false,
        ...wireError(error),
      });
    }
  }

  /** The annotated return type keeps the switch exhaustive over `WireRead`. */
  private readValue(read: WireRead): Promise<SnapshotDescriptor | ArrayBuffer | string> {
    switch (read.kind) {
      case 'snapshot':
        return this.transport.snapshot(read.folder);
      case 'siweChallenge':
        return this.transport.siweChallenge();
      case 'download':
        return this.transport.download(read.node);
    }
  }

  private postPort(
    port: MessagePortLike,
    message: ReadPortResponse,
    transfer?: Transferable[]
  ): void {
    if (this.closed) return;
    port.postMessage(message, transfer);
  }

  private detachPortOf(clientId: string): void {
    for (const entry of this.readPorts) if (entry.clientId === clientId) this.detachPort(entry);
  }

  private detachPort(entry: ReadPortEntry): void {
    clearTimeout(entry.naming);
    this.readPorts.delete(entry);
    this.postPort(entry.port, { type: 'cb:portClosed' });
    entry.port.removeEventListener('message', entry.listener);
    entry.port.close();
  }

  private serveWrite(message: Extract<FollowerMessage, { type: 'cb:write' }>): void {
    const { clientId, requestId, write } = message;
    const ack: Ack = { type: 'cb:response', token: this.token, clientId, requestId };

    if (write.kind === 'beginWrite') {
      void this.answerStep(ack, () =>
        this.bind(
          'write',
          clientId,
          this.transport.beginWrite(write.target, write.size),
          (handle) => this.transport.abortWrite(handle)
        )
      );
      return;
    }

    const handle = write.handle;
    if (this.writeOwners.get(handle) !== clientId) {
      this.post({ ...ack, ok: false, ...wireError(unknownHandle('write')) });
      return;
    }

    // Enqueued synchronously, before any await: `WriteQueue` orders a handle's
    // steps by call order.
    void this.writes.run(handle, () =>
      this.answerStep(ack, async () => {
        switch (write.kind) {
          case 'pushChunk':
            // Materialize the follower's shared `Blob` only here, then transfer
            // the buffer into the worker.
            return this.transport.pushChunk(handle, await write.chunk.arrayBuffer());
          case 'commitWrite': {
            const opId = await this.transport.commitWrite(handle);
            // Dropped only once the commit resolves: a rejected one leaves the
            // handle open for its owner to abort.
            this.writeOwners.delete(handle);
            return opId;
          }
          case 'abortWrite':
            await this.transport.abortWrite(handle);
            // Dropped only once the abort resolves: a rejected one leaves the
            // handle owned so it can still be retried or released.
            this.writeOwners.delete(handle);
            return;
        }
      })
    );
  }

  /** One ranged-read step, owned by the tab holding the port it arrived on. */
  private async streamStep(
    clientId: string,
    stream: WireStream
  ): Promise<StreamHandle | ArrayBuffer | undefined> {
    if (stream.kind === 'openContentStream') {
      return this.bind(
        'stream',
        clientId,
        this.transport.openContentStream(stream.node),
        (handle) => this.transport.closeStream(handle)
      );
    }

    const handle = stream.handle;
    if (this.streamOwners.get(handle) !== clientId) throw unknownHandle('stream');

    if (stream.kind === 'closeStream') {
      await this.transport.closeStream(handle);
      // Dropped only once the close resolves: a rejected one leaves the handle
      // owned, so the release sweep still knows to free the pin it holds.
      this.streamOwners.delete(handle);
      return undefined;
    }
    return this.transport.readStream(handle, stream.offset, stream.length);
  }

  /** Runs one handle-bound step and posts its correlated ack. */
  private async answerStep(ack: Ack, step: () => Promise<bigint | void>): Promise<void> {
    try {
      const result = await step();
      this.post(result === undefined ? { ...ack, ok: true } : { ...ack, ok: true, result });
    } catch (error) {
      this.post({ ...ack, ok: false, ...wireError(error) });
    }
  }

  /**
   * Records the minted handle against the client that asked for it, releasing it
   * instead if that client (or this relay) left while the mint was in flight.
   */
  private async bind(
    kind: HandleKind,
    clientId: string,
    minting: Promise<bigint>,
    close: (handle: bigint) => Promise<unknown>
  ): Promise<bigint> {
    this.mintsInFlight.set(clientId, (this.mintsInFlight.get(clientId) ?? 0) + 1);
    try {
      const handle = await minting;
      if (this.closed || this.departed.has(clientId)) {
        void close(handle).catch(() => undefined);
        throw unknownHandle(kind);
      }
      this.owners(kind).set(handle, clientId);
      return handle;
    } finally {
      this.endMint(clientId);
    }
  }

  /** Drops the `departed` guard once the last mint it covered has settled. */
  private endMint(clientId: string): void {
    const left = (this.mintsInFlight.get(clientId) ?? 1) - 1;
    if (left > 0) {
      this.mintsInFlight.set(clientId, left);
      return;
    }
    this.mintsInFlight.delete(clientId);
    this.departed.delete(clientId);
  }

  private owners(kind: HandleKind): Map<bigint, string> {
    return kind === 'write' ? this.writeOwners : this.streamOwners;
  }

  /**
   * Abandons handles this relay can no longer serve — `clientId`'s, or all of
   * them on teardown. A stranded write handle holds its byte reservation against
   * the staging ledger for the rest of the session, so every later write on every
   * tab is refused as over-budget; a stranded read stream pins its content
   * version in the engine just as long.
   */
  private releaseHandles(clientId: string | null): void {
    this.release('write', clientId, (handle) =>
      this.writes.run(handle, () => this.transport.abortWrite(handle))
    );
    this.release('stream', clientId, (handle) => this.transport.closeStream(handle));
  }

  private release(
    kind: HandleKind,
    clientId: string | null,
    close: (handle: bigint) => Promise<unknown>
  ): void {
    const owners = this.owners(kind);
    for (const [handle, owner] of owners) {
      if (clientId !== null && owner !== clientId) continue;
      owners.delete(handle);
      void close(handle).catch(() => undefined);
    }
  }

  /**
   * A tab's focus changed the union: forward a manual-refresh hint to the
   * engine. This is the RefreshHintSource seam (a best-effort accelerator), not
   * a new command semantic — a dropped hint costs staleness, never correctness.
   */
  private refreshHint(): void {
    void this.transport.command({ kind: 'manualRefresh' }, []).catch(() => undefined);
  }

  private post(message: LeaderMessage): void {
    if (this.closed) return;
    this.channel.postMessage(message);
  }
}
