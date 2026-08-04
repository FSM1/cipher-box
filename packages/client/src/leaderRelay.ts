/**
 * The leader-side relay (blueprint/web-client.md "Engine hosting and tab
 * leadership"). The leader owns the single engine worker over its
 * `LocalTransport`; this relay bridges that worker to follower tabs:
 *
 * - follower command / read / write step → the leader's worker → correlated
 *   result back, all over that follower's private `PortCourier` port;
 * - every engine event → fanned out to all followers over the channel, in
 *   emission order;
 * - each tab's open folder → the leader's **focus-window union**, so freshness
 *   follows whichever tab is focused (the RefreshHintSource seam, cross-tab).
 *
 * Nothing value-bearing touches the `BroadcastChannel` in either direction: it
 * carries election, the port rendezvous, and key-free `EventDescriptor`s. One
 * port per follower per leadership.
 */

import type {
  BroadcastChannelLike,
  FollowerMessage,
  LeaderMessage,
  PortRequest,
  PortResponse,
  WireRead,
  WireStream,
  WireWrite,
} from './broadcast.js';
import { EngineRequestError, unknownHandle, type HandleKind } from './correlatedTransport.js';
import type { MessagePortLike, PortCourier } from './portRelay.js';
import type { EngineTransport } from './transport.js';
import type { SnapshotDescriptor, StreamHandle, WriteHandle } from './worker/protocol.js';
import { WriteQueue } from './writeQueue.js';

/** One follower's private port, with the listener bound to it. */
interface PortEntry {
  readonly port: MessagePortLike;
  readonly listener: (event: MessageEvent) => void;
  clientId: string | null;
  /** Reclaims a port that never named itself, so an unnamed one cannot pile up. */
  readonly naming: ReturnType<typeof setTimeout>;
  /** Consecutive liveness sweeps this port has not answered. */
  missed: number;
}

export interface LeaderRelayOptions {
  /** How long a freshly dialed port has to name the follower behind it. */
  namingTimeoutMs?: number;
  /** How often the leader probes each named port for the tab behind it. */
  livenessIntervalMs?: number;
  /** Consecutive unanswered probes before a follower is presumed dead. */
  livenessMisses?: number;
}

const DEFAULT_NAMING_TIMEOUT_MS = 5000;
// Generous by design: a backgrounded tab's timers are throttled, and a
// false positive tears down a live tab's in-flight media playback.
const DEFAULT_LIVENESS_INTERVAL_MS = 15_000;
const DEFAULT_LIVENESS_MISSES = 4;

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
  private readonly ports = new Set<PortEntry>();
  private readonly namingTimeoutMs: number;
  private readonly livenessMisses: number;
  private readonly liveness: ReturnType<typeof setInterval>;
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
    this.livenessMisses = options.livenessMisses ?? DEFAULT_LIVENESS_MISSES;
    this.liveness = setInterval(
      () => this.sweepLiveness(),
      options.livenessIntervalMs ?? DEFAULT_LIVENESS_INTERVAL_MS
    );
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
    clearInterval(this.liveness);
    for (const entry of [...this.ports]) this.detachPort(entry);
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
      case 'cb:portWanted':
        void this.announceHost();
        return;
      case 'cb:focus': {
        const { clientId, node } = message as Extract<FollowerMessage, { type: 'cb:focus' }>;
        if (this.focus.set(clientId, node)) this.refreshHint();
        return;
      }
      case 'cb:bye':
        this.reclaim((message as Extract<FollowerMessage, { type: 'cb:bye' }>).clientId);
        return;
    }
  }

  /**
   * Abandons everything a follower held: its focus, its write and stream
   * handles, and its port. Driven by `cb:bye` and by the liveness sweep, which
   * is the only signal a crashed tab leaves behind.
   */
  private reclaim(clientId: string): void {
    if (this.focus.remove(clientId)) this.refreshHint();
    // Only a mint `releaseHandles` cannot see needs guarding.
    if (this.mintsInFlight.has(clientId)) this.departed.add(clientId);
    this.releaseHandles(clientId);
    this.detachPortOf(clientId);
  }

  /**
   * Probes each named port and reclaims the follower behind one that has stopped
   * answering. A tab that dies without `cb:bye` — a crash, a force-quit, a killed
   * renderer — otherwise strands its handles, and a stranded stream holds a
   * content version and its key resident for the rest of the leadership.
   *
   * The probe is answered from a message handler, not a timer, so a throttled
   * background tab still proves itself; any port traffic at all counts, so a tab
   * mid-playback is never a candidate.
   */
  private sweepLiveness(): void {
    for (const entry of [...this.ports]) {
      if (entry.clientId === null) continue; // the naming timeout owns unnamed ports
      if (entry.missed >= this.livenessMisses) {
        this.reclaim(entry.clientId);
        continue;
      }
      entry.missed += 1;
      this.postPort(entry.port, { type: 'cb:portPing' });
    }
  }

  /**
   * Publishes where this leadership takes follower ports. A follower dials it
   * rather than publishing an address of its own, so no context can push a port
   * at a tab that never asked for one. Silent without a broker: the asking
   * follower's request then fails closed on its own gate.
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
    const entry: PortEntry = {
      port,
      clientId: null,
      listener: (event) => this.onPortMessage(entry, event.data),
      naming: setTimeout(() => this.detachPort(entry), this.namingTimeoutMs),
      missed: 0,
    };
    port.addEventListener('message', entry.listener);
    port.start?.();
    this.ports.add(entry);
  }

  /** A same-origin port is untrusted input: anything off-shape is dropped. */
  private onPortMessage(entry: PortEntry, data: unknown): void {
    if (this.closed) return;
    // Any traffic at all proves the tab behind this port is still running.
    entry.missed = 0;
    const message = data as PortRequest | { type?: unknown };
    if (message.type === 'cb:portPong') return;
    if (message.type === 'cb:portHello') {
      const { clientId } = message as Extract<PortRequest, { type: 'cb:portHello' }>;
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
    // A port serves requests only once named — that name is how a departure
    // reclaims it, and how a step is bound to the tab that owns the handle.
    const clientId = entry.clientId;
    if (clientId === null) return;
    const requestId = (message as { requestId?: unknown }).requestId;
    if (typeof requestId !== 'number') return;
    switch (message.type) {
      case 'cb:portRead': {
        const { read } = message as Extract<PortRequest, { type: 'cb:portRead' }>;
        void this.answerPort(entry, requestId, () => this.readValue(read));
        return;
      }
      case 'cb:portStream': {
        const { stream } = message as Extract<PortRequest, { type: 'cb:portStream' }>;
        void this.answerPort(entry, requestId, () => this.streamStep(clientId, stream));
        return;
      }
      case 'cb:portCommand': {
        const { command } = message as Extract<PortRequest, { type: 'cb:portCommand' }>;
        void this.answerPort(entry, requestId, () =>
          this.transport.command(command, []).then(() => undefined)
        );
        return;
      }
      case 'cb:portWrite': {
        const { write } = message as Extract<PortRequest, { type: 'cb:portWrite' }>;
        this.serveWrite(entry, requestId, clientId, write);
        return;
      }
    }
  }

  /** Runs one port-borne step and posts its correlated result down that port. */
  private async answerPort(
    entry: PortEntry,
    requestId: number,
    step: () => Promise<SnapshotDescriptor | ArrayBuffer | string | bigint | undefined>
  ): Promise<void> {
    try {
      const result = await step();
      if (this.closed || !this.ports.has(entry)) {
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

  private postPort(port: MessagePortLike, message: PortResponse, transfer?: Transferable[]): void {
    if (this.closed) return;
    port.postMessage(message, transfer);
  }

  private detachPortOf(clientId: string): void {
    for (const entry of this.ports) if (entry.clientId === clientId) this.detachPort(entry);
  }

  private detachPort(entry: PortEntry): void {
    clearTimeout(entry.naming);
    this.ports.delete(entry);
    this.postPort(entry.port, { type: 'cb:portClosed' });
    entry.port.removeEventListener('message', entry.listener);
    entry.port.close();
  }

  /** One write step, owned by the tab holding the port it arrived on. */
  private serveWrite(
    entry: PortEntry,
    requestId: number,
    clientId: string,
    write: WireWrite
  ): void {
    if (write.kind === 'beginWrite') {
      void this.answerPort(entry, requestId, () =>
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
      // The chunk was transferred here, so this frame is its last owner
      // (AGENTS.md 7): wipe the plaintext rather than leave it for the collector.
      if (write.kind === 'pushChunk') new Uint8Array(write.chunk).fill(0);
      this.postPort(entry.port, {
        type: 'cb:portResult',
        requestId,
        ok: false,
        ...wireError(unknownHandle('write')),
      });
      return;
    }

    // Enqueued synchronously, before any await: `WriteQueue` orders a handle's
    // steps by call order.
    void this.writes.run(handle, () =>
      this.answerPort(entry, requestId, async () => {
        switch (write.kind) {
          case 'pushChunk':
            // Transferred in, transferred on: the plaintext is never copied.
            await this.transport.pushChunk(handle, write.chunk);
            return undefined;
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
            return undefined;
        }
      })
    );
  }

  /** One `readStream` step, owned by the tab holding the port it arrived on. */
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
