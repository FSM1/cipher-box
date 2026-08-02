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
 * `EventDescriptor`s and command/write acks. Read results go to the private
 * `PortCourier` port that follower dialed, one per follower per leadership. The
 * follower→leader direction is unchanged and still broadcasts command arguments
 * and upload chunks.
 */

import type {
  BroadcastChannelLike,
  FollowerMessage,
  LeaderMessage,
  ReadPortRequest,
  ReadPortResponse,
  WireRead,
} from './broadcast.js';
import { EngineRequestError } from './correlatedTransport.js';
import type { MessagePortLike, PortCourier } from './portRelay.js';
import type { EngineTransport } from './transport.js';
import type { SnapshotDescriptor, WriteHandle } from './worker/protocol.js';
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
    this.closed = true;
    this.releaseWrites(null);
    this.unsubscribePorts();
    for (const entry of [...this.readPorts]) this.detachPort(entry);
    this.unsubscribe();
    this.channel.removeEventListener('message', this.onMessage);
  }

  private receive(message: FollowerMessage | { type?: string }): void {
    if (this.closed) return;
    switch (message.type) {
      case 'cb:hello':
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
        this.releaseWrites(clientId);
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
      // A re-brokering follower supersedes the port it held before.
      this.detachPortOf(clientId);
      clearTimeout(entry.naming);
      entry.clientId = clientId;
      this.postPort(entry.port, { type: 'cb:portReady', token: this.token });
      return;
    }
    // A port serves reads only once named — that name is how `cb:bye` reclaims it.
    if (entry.clientId === null || message.type !== 'cb:portRead') return;
    const { requestId, read } = message as Extract<ReadPortRequest, { type: 'cb:portRead' }>;
    if (typeof requestId !== 'number') return;
    void this.serveRead(entry.port, requestId, read);
  }

  private async serveRead(port: MessagePortLike, requestId: number, read: WireRead): Promise<void> {
    try {
      const result = await this.readValue(read);
      // Transferred, not cloned: the plaintext leaves this tab's heap outright.
      this.postPort(
        port,
        { type: 'cb:portResult', requestId, ok: true, result },
        result instanceof ArrayBuffer ? [result] : undefined
      );
    } catch (error) {
      this.postPort(port, { type: 'cb:portResult', requestId, ok: false, ...wireError(error) });
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
      case 'downloadRange':
        return this.transport.downloadRange(read.node, read.offset, read.length);
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
      void this.answerWrite(ack, async () => {
        const handle = await this.transport.beginWrite(write.target, write.size);
        this.writeOwners.set(handle, clientId);
        return handle;
      });
      return;
    }

    const handle = write.handle;
    if (this.writeOwners.get(handle) !== clientId) {
      this.post({ ...ack, ok: false, error: 'unknown write handle', code: 'unknownWriteHandle' });
      return;
    }

    // Enqueued synchronously, before any await: `WriteQueue` orders a handle's
    // steps by call order.
    void this.writes.run(handle, () =>
      this.answerWrite(ack, async () => {
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

  /** Runs one write step and posts its correlated ack. */
  private async answerWrite(ack: Ack, step: () => Promise<bigint | void>): Promise<void> {
    try {
      const result = await step();
      this.post(typeof result === 'bigint' ? { ...ack, ok: true, result } : { ...ack, ok: true });
    } catch (error) {
      this.post({ ...ack, ok: false, ...wireError(error) });
    }
  }

  /**
   * Abandons handles this relay can no longer serve — `clientId`'s, or all of
   * them on teardown. A stranded handle holds its byte reservation against the
   * staging ledger for the rest of the session, so every later write on every
   * tab is refused as over-budget.
   */
  private releaseWrites(clientId: string | null): void {
    for (const [handle, owner] of this.writeOwners) {
      if (clientId !== null && owner !== clientId) continue;
      this.writeOwners.delete(handle);
      void this.writes.run(handle, () => this.transport.abortWrite(handle)).catch(() => undefined);
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
