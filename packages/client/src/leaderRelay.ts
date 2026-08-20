/**
 * The leader-side relay (blueprint/web-client.md "Engine hosting and tab
 * leadership"). The leader owns the single engine worker over its
 * `LocalTransport`; this relay bridges that worker to follower tabs:
 *
 * - follower command / read / write step → the leader's worker → correlated
 *   result back, all over that follower's private `PortCourier` port;
 * - every engine event → fanned out over those same ports, in emission order;
 * - each tab's open folder → the leader's **focus-window union**, so freshness
 *   follows whichever tab is focused, cross-tab.
 *
 * Nothing that names or measures vault content touches the `BroadcastChannel`
 * in either direction: it carries election and the port rendezvous only. One
 * port per follower per leadership.
 *
 * The channel is a **rendezvous, not an authority**: every same-origin context
 * can read and write it, so the leadership token fences one leadership from the
 * next and authenticates nothing. Each trust decision rests on something the
 * channel cannot forge — a request is served only over the port the follower
 * itself dialed, and a departure only on the release of that follower's
 * presence lock, which no other context can give up on its behalf.
 */

import {
  presenceLockName,
  type BroadcastChannelLike,
  type FollowerMessage,
  type LeaderMessage,
  type PortRequest,
  type PortResponse,
  type WireRead,
  type WireStream,
  type WireWrite,
} from './broadcast.js';
import { EngineRequestError, unknownHandle, type HandleKind } from './correlatedTransport.js';
import type { LockManagerLike } from './leadership.js';
import type { MessagePortLike, PortCourier } from './portRelay.js';
import type { EngineTransport } from './transport.js';
import type {
  CommandOutcomeDescriptor,
  EventDescriptor,
  SnapshotDescriptor,
  StreamHandle,
  WriteHandle,
} from './worker/protocol.js';
import { WriteQueue } from './writeQueue.js';

/** One follower's private port, with the listener bound to it. */
interface PortEntry {
  readonly port: MessagePortLike;
  readonly listener: (event: MessageEvent) => void;
  clientId: string | null;
  /** The account this port greeted under; only that engine may answer on it. */
  accountId: string | null;
  /** Reclaims a port that never named itself, so an unnamed one cannot pile up. */
  readonly naming: ReturnType<typeof setTimeout>;
}

export interface LeaderRelayOptions {
  /** How long a freshly dialed port has to name the follower behind it. */
  namingTimeoutMs?: number;
}

const DEFAULT_NAMING_TIMEOUT_MS = 5000;

/**
 * Wipes the upload chunk a write payload carries. A chunk arrives transferred,
 * so the relay is its terminal owner until a further transfer detaches it — and
 * a detached buffer reads as empty, making this a no-op once it has moved on
 * (AGENTS.md 7). Takes the payload unvalidated: an off-shape one carries none.
 */
function wipeCarried(payload: unknown): void {
  const chunk = (payload as { chunk?: unknown } | null | undefined)?.chunk;
  if (chunk instanceof ArrayBuffer && chunk.byteLength > 0) new Uint8Array(chunk).fill(0);
}

/**
 * Whether an unvalidated payload carries the `kind` its handler switches on.
 * Shape only: which kinds exist, and what their fields must be, is the engine's
 * and the codec's to say.
 */
function hasKind(payload: unknown): boolean {
  return typeof (payload as { kind?: unknown } | null | undefined)?.kind === 'string';
}

/**
 * Exhaustiveness bound: fails the build if the union grows a variant, and gives
 * a sender off the union a refusal rather than an unhandled fall-through.
 */
function unknownKind(_: never): EngineRequestError {
  return malformed();
}

/**
 * Refuses a request this relay cannot make sense of — a hostile sender, or a
 * version-skewed follower build. Transport-level, so it carries no engine code.
 */
function malformed(): EngineRequestError {
  return new EngineRequestError('malformed engine request');
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
  private readonly ports = new Set<PortEntry>();
  // One presence watch per named follower, keyed on the client rather than the
  // port so a re-brokering tab keeps the watch it already proved alive under.
  private readonly presence = new Map<string, AbortController>();
  private readonly namingTimeoutMs: number;
  // The account this leadership's engine holds; `null` until it cold-starts.
  private account: string | null = null;
  private readonly unsubscribe: () => void;
  private readonly unsubscribePorts: () => void;
  private closed = false;
  // Focus-driven refresh collapse: at most one pass in flight, at most one
  // trailing pass behind it (see `forceRefresh`).
  private refreshInFlight = false;
  private refreshTrailing = false;
  // Stamps every leader→follower message so a follower can tell this leadership
  // from the one before it, and drop a stale beacon.
  private readonly token = globalThis.crypto.randomUUID();
  private readonly onMessage = (event: MessageEvent): void => this.receive(event.data);

  constructor(
    private readonly channel: BroadcastChannelLike,
    private readonly transport: EngineTransport,
    private readonly courier: PortCourier,
    private readonly locks: LockManagerLike,
    options: LeaderRelayOptions = {}
  ) {
    this.namingTimeoutMs = options.namingTimeoutMs ?? DEFAULT_NAMING_TIMEOUT_MS;
    this.channel.addEventListener('message', this.onMessage);
    this.unsubscribePorts = this.courier.onPort((port) => this.adoptPort(port));
    this.unsubscribe = this.transport.subscribe((event) => this.fanOut(event));
    // Announce leadership so followers (existing or newly-elected-away) reconnect.
    this.post({ type: 'cb:leader', token: this.token });
  }

  /**
   * Names the account this leadership's engine cold-started for. The origin
   * hosts a single engine, so it hosts a single account (blueprint/web-client.md
   * "Engine hosting and tab leadership"): this relay serves only followers that
   * greet under the same one, and a follower adopted under the account it held
   * before is reclaimed here — the same abandonment a departure drives, since a
   * write it still owns would otherwise hold its staging reservation for the
   * rest of the session against an engine that will never serve it again.
   */
  serves(accountId: string | null): void {
    if (this.account === accountId) return;
    this.account = accountId;
    for (const entry of [...this.ports]) {
      if (entry.clientId !== null && entry.accountId !== accountId) this.reclaim(entry.clientId);
    }
  }

  /** Folds the leader tab's own open folder into the focus-window union. */
  reportLocalFocus(clientId: string, node: Uint8Array | null): void {
    if (this.closed) return;
    if (this.focus.set(clientId, node)) this.forceRefresh();
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
    for (const watch of this.presence.values()) watch.abort();
    this.presence.clear();
    for (const entry of [...this.ports]) this.detachPort(entry);
    this.closed = true;
    this.releaseHandles(null);
    this.unsubscribe();
    this.channel.removeEventListener('message', this.onMessage);
  }

  private receive(data: unknown): void {
    if (this.closed || typeof data !== 'object' || data === null) return;
    const message = data as FollowerMessage | { type?: string };
    switch (message.type) {
      case 'cb:hello':
        this.post({ type: 'cb:leader', token: this.token });
        return;
      case 'cb:portWanted':
        void this.announceHost();
        return;
    }
  }

  /** Every engine event, to every adopted port, in emission order. */
  private fanOut(event: EventDescriptor): void {
    for (const entry of this.ports) {
      if (entry.clientId !== null) this.postPort(entry.port, { type: 'cb:portEvent', event });
    }
  }

  /**
   * Abandons everything a follower held: its focus, its write and stream
   * handles, and its port. Driven by the presence watch, which is the only
   * departure signal no other same-origin context can give on its behalf.
   */
  private reclaim(clientId: string): void {
    this.retirePresence(clientId);
    if (this.focus.remove(clientId)) this.forceRefresh();
    this.releaseHandles(clientId);
    this.detachPortOf(clientId);
  }

  /**
   * Watches for the death of the tab behind a named port. The follower holds its
   * presence lock from before it greets until its tab closes, crashes or is
   * discarded, so this request is granted at exactly the moment the tab is gone
   * — an event-driven death signal, in place of a probe a live-but-frozen tab
   * would fail. A follower that greets without holding the lock is granted
   * immediately and reclaimed, so the greeting cannot outlive the presence.
   */
  private watchPresence(clientId: string): void {
    if (this.presence.has(clientId)) return;
    const watch = new AbortController();
    this.presence.set(clientId, watch);
    void this.locks
      .request(presenceLockName(clientId), { signal: watch.signal, mode: 'exclusive' }, () => {
        this.reclaim(clientId);
        // Released at once: the watch is the grant, not a lock to hold.
        return Promise.resolve();
      })
      .catch(() => undefined); // an aborted watch is the retirement path
  }

  private retirePresence(clientId: string): void {
    const watch = this.presence.get(clientId);
    if (!watch) return;
    this.presence.delete(clientId);
    watch.abort();
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
      accountId: null,
      listener: (event) => this.onPortMessage(entry, event.data),
      naming: setTimeout(() => this.detachPort(entry), this.namingTimeoutMs),
    };
    port.addEventListener('message', entry.listener);
    port.start?.();
    this.ports.add(entry);
  }

  private onPortMessage(entry: PortEntry, data: unknown): void {
    if (typeof data !== 'object' || data === null) return;
    const message = data as PortRequest | { type?: unknown };
    if (!this.serve(entry, message)) wipeCarried((message as { write?: unknown }).write);
  }

  /**
   * Serves one port message; `false` when it was dropped unserved. A port is
   * untrusted input, so an off-shape message is refused where it names a request
   * this relay can answer, and dropped where it does not: a drop is a silence
   * the sender waits out.
   */
  private serve(entry: PortEntry, message: PortRequest | { type?: unknown }): boolean {
    if (this.closed) return false;
    if (message.type === 'cb:portHello') {
      const { clientId, accountId } = message as Extract<PortRequest, { type: 'cb:portHello' }>;
      if (entry.clientId !== null || typeof clientId !== 'string') return false;
      if (accountId !== null && typeof accountId !== 'string') return false;
      // Serving a greeting that names another account would put that tab's UI on
      // this engine's vault — a cross-account read inside one browser profile.
      // Refused, and told which account holds the engine, so the tab can say so.
      if (accountId !== this.account) {
        this.postPort(entry.port, {
          type: 'cb:portRefused',
          token: this.token,
          accountId: this.account,
        });
        this.detachPort(entry);
        return true;
      }
      // A re-brokering follower supersedes the port it held before; whatever it
      // had in flight there is retired with that entry.
      this.detachPortOf(clientId);
      clearTimeout(entry.naming);
      entry.clientId = clientId;
      entry.accountId = accountId;
      this.watchPresence(clientId);
      this.postPort(entry.port, { type: 'cb:portReady', token: this.token });
      return true;
    }
    // A port serves requests only once named — that name is how a departure
    // reclaims it, and how a step is bound to the tab that owns the handle.
    const clientId = entry.clientId;
    if (clientId === null) return false;
    if (message.type === 'cb:portFocus') {
      const { node } = message as Extract<PortRequest, { type: 'cb:portFocus' }>;
      // Uncorrelated, so nothing to refuse; the registry keys on the bytes.
      if (node !== null && !(node instanceof Uint8Array)) return false;
      if (this.focus.set(clientId, node)) this.forceRefresh();
      return true;
    }
    const requestId = (message as { requestId?: unknown }).requestId;
    if (typeof requestId !== 'number') return false;
    switch (message.type) {
      case 'cb:portRead': {
        const { read } = message as Extract<PortRequest, { type: 'cb:portRead' }>;
        if (!hasKind(read)) return this.refuse(entry, requestId, message);
        void this.answerPort(entry, requestId, () => this.readValue(read));
        return true;
      }
      case 'cb:portStream': {
        const { stream } = message as Extract<PortRequest, { type: 'cb:portStream' }>;
        if (!hasKind(stream)) return this.refuse(entry, requestId, message);
        void this.answerPort(entry, requestId, () => this.streamStep(entry, clientId, stream));
        return true;
      }
      case 'cb:portCommand': {
        const { command } = message as Extract<PortRequest, { type: 'cb:portCommand' }>;
        if (!hasKind(command)) return this.refuse(entry, requestId, message);
        void this.answerPort(entry, requestId, () => this.transport.command(command, []));
        return true;
      }
      case 'cb:portWrite': {
        const { write } = message as Extract<PortRequest, { type: 'cb:portWrite' }>;
        if (!hasKind(write)) return this.refuse(entry, requestId, message);
        this.serveWrite(entry, requestId, clientId, write);
        return true;
      }
    }
    return this.refuse(entry, requestId, message);
  }

  /** Refuses a request this relay will not serve, wiping anything it carried. */
  private refuse(entry: PortEntry, requestId: number, message: unknown): true {
    wipeCarried((message as { write?: unknown } | null)?.write);
    void this.answerPort(entry, requestId, () => Promise.reject(malformed()));
    return true;
  }

  /** Runs one port-borne step and posts its correlated result down that port. */
  private async answerPort(
    entry: PortEntry,
    requestId: number,
    step: () => Promise<
      SnapshotDescriptor | CommandOutcomeDescriptor | ArrayBuffer | string | bigint | undefined
    >
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

  private readValue(read: WireRead): Promise<SnapshotDescriptor | ArrayBuffer | string> {
    switch (read.kind) {
      case 'snapshot':
        return this.transport.snapshot(read.folder);
      case 'siweChallenge':
        return this.transport.siweChallenge();
      case 'download':
        return this.transport.download(read.node);
      default:
        return Promise.reject(unknownKind(read));
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
          entry,
          clientId,
          this.transport.beginWrite(write.target, write.size),
          (handle) => this.transport.abortWrite(handle)
        )
      );
      return;
    }

    const handle = write.handle;
    if (this.writeOwners.get(handle) !== clientId) {
      wipeCarried(write);
      void this.answerPort(entry, requestId, () => Promise.reject(unknownHandle('write')));
      return;
    }

    // Enqueued synchronously, before any await: `WriteQueue` orders a handle's
    // steps by call order.
    void this.writes.run(handle, () =>
      this.answerPort(entry, requestId, async () => {
        try {
          switch (write.kind) {
            case 'pushChunk':
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
            default:
              throw unknownKind(write);
          }
        } finally {
          wipeCarried(write);
        }
      })
    );
  }

  /** One `readStream` step, owned by the tab holding the port it arrived on. */
  private async streamStep(
    entry: PortEntry,
    clientId: string,
    stream: WireStream
  ): Promise<StreamHandle | ArrayBuffer | undefined> {
    if (stream.kind === 'openContentStream') {
      return this.bind(
        'stream',
        entry,
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
    if (stream.kind !== 'readStream') throw unknownKind(stream);
    return this.transport.readStream(handle, stream.offset, stream.length);
  }

  /**
   * Records the minted handle against the client that asked for it, releasing it
   * instead if the port it was minted for is gone.
   *
   * A mint completes after an await, so the release sweep may already have run
   * against a table the handle had not landed in yet. The entry is the test that
   * covers every such case at once — a departure, a step-down, and a follower
   * that re-brokered mid-mint all retire it — and a handle its owner will never
   * receive is a handle nothing will ever release.
   */
  private async bind(
    kind: HandleKind,
    entry: PortEntry,
    clientId: string,
    minting: Promise<bigint>,
    close: (handle: bigint) => Promise<unknown>
  ): Promise<bigint> {
    const handle = await minting;
    if (!this.ports.has(entry)) {
      void close(handle).catch(() => undefined);
      throw unknownHandle(kind);
    }
    this.owners(kind).set(handle, clientId);
    return handle;
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
   * A tab's focus changed the union: force a pass over the new window. A burst
   * of union changes collapses onto one trailing pass rather than queueing a
   * network pass per change — the engine serializes commands, so a stacked
   * burst would park every other call behind it. The relay is an accelerator,
   * so a refusal costs staleness, never correctness: the tab that asked for a
   * refresh reports its own failures.
   */
  private forceRefresh(): void {
    // A pass in flight at close settles afterwards and would dispatch its
    // trailing pass from a relay that has already stepped down.
    if (this.closed) return;
    if (this.refreshInFlight) {
      this.refreshTrailing = true;
      return;
    }
    this.refreshInFlight = true;
    void this.transport
      .command({ kind: 'manualRefresh' }, [])
      .catch(() => undefined)
      .finally(() => {
        this.refreshInFlight = false;
        if (!this.refreshTrailing) return;
        this.refreshTrailing = false;
        this.forceRefresh();
      });
  }

  private post(message: LeaderMessage): void {
    if (this.closed) return;
    this.channel.postMessage(message);
  }
}
