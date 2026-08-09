/**
 * The follower-side `EngineTransport` (blueprint/web-client.md "Followers are
 * thin mirrors"). A non-leader tab holds no worker and no keys: it sends
 * commands as data to the leader and renders the projections it serves and the
 * events it broadcasts back.
 *
 * It honors the same teardown contract as `LocalTransport`: a torn-down or
 * leader-dead transport **rejects** every pending request, never hangs — so a
 * command caught in flight at a leadership swap surfaces a retry to the UI
 * rather than silently disappearing.
 *
 * A follower authenticates the leader by an unguessable per-leadership `token`
 * carried on the `cb:leader` beacon: it stamps every accepted event and the port
 * rendezvous, and lets the follower reject forgeries from a non-leader
 * same-origin context.
 *
 * Every exchange that names or measures vault content takes a different wire:
 * the channel only rendezvouses a private `MessagePort` this tab dials to the
 * leader, and command arguments, upload chunks, snapshots, plaintext windows and
 * the engine event stream all cross it — so a same-origin context that merely
 * opened the channel is no longer a receiver. The rendezvous is as authenticated
 * as the `cb:leader` beacon and no more: same origin remains the trust boundary.
 *
 * The tab also holds a **presence lock** for its whole life, released by the
 * browser when it dies; the leader watches that release to reclaim what this tab
 * held. It is taken before the greeting, so the leader never watches a name no
 * one holds.
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
import { CorrelatedTransport } from './correlatedTransport.js';
import { asError } from './errorMessage.js';
import type { LockManagerLike } from './leadership.js';
import type { MessagePortLike, PortCourier } from './portRelay.js';
import type {
  CommandDescriptor,
  SnapshotDescriptor,
  StreamHandle,
  WriteHandle,
  WriteTarget,
} from './worker/protocol.js';

/** How long a follower waits on each step of brokering its private port. */
const DEFAULT_PORT_TIMEOUT_MS = 5000;

export interface BroadcastTransportOptions {
  portTimeoutMs?: number;
  /**
   * Fires when leadership moves while this tab stays a follower. The engine
   * behind this transport is replaced but the transport object is not, so
   * whatever the owner holds against the old engine has to be retired here.
   */
  onLeadershipChange?: () => void;
}

export class BroadcastTransport extends CorrelatedTransport {
  private closed = false;

  // The active leadership's capability token; `null` when no leader is known
  // (start, or after the leader stepped down). Only messages bearing this exact
  // token are accepted.
  private leaderToken: string | null = null;
  // Re-armed on every leadership change so a command posted while no leader is
  // present awaits the *next* leader instead of resolving against a dead one.
  private leaderReady!: Promise<void>;
  private resolveLeaderReady!: () => void;
  private rejectLeaderReady!: (error: Error) => void;

  // The private port to the current leadership, re-brokered from scratch whenever
  // leadership moves. `portGeneration` fences a broker still in flight across
  // that move, so a read never lands on a port the departed leader served.
  private portPromise: Promise<MessagePortLike> | null = null;
  private releasePort: (() => void) | null = null;
  private portGeneration = 0;
  // The parked brokerage step. `abortBrokerage` lets teardown and a leadership
  // swap settle it at once instead of leaving a read to wait out the timeout.
  private abortBrokerage: ((error: Error) => void) | null = null;
  private settleHost: ((address: string) => void) | null = null;
  private settleBrokerage: (() => void) | null = null;
  private readonly portTimeoutMs: number;
  private readonly onLeadershipChange: () => void;

  private readonly presenceHeld: Promise<void>;
  private readonly presenceRequest = new AbortController();
  private releasePresence: (() => void) | null = null;
  // Set if the presence request ever settles in failure — including a lock
  // stolen out from under a live tab, which the browser reports here.
  private presenceLost: Error | null = null;

  private readonly onMessage = (event: MessageEvent): void => this.receive(event.data);

  constructor(
    private readonly channel: BroadcastChannelLike,
    private readonly clientId: string,
    private readonly courier: PortCourier,
    locks: LockManagerLike,
    options: BroadcastTransportOptions = {}
  ) {
    super();
    this.portTimeoutMs = options.portTimeoutMs ?? DEFAULT_PORT_TIMEOUT_MS;
    this.onLeadershipChange = options.onLeadershipChange ?? ((): void => undefined);
    this.presenceHeld = this.holdPresence(locks);
    this.armLeaderReady();
    this.channel.addEventListener('message', this.onMessage);
    // Announce ourselves so a live leader replies with a `leader` beacon.
    this.post({ type: 'cb:hello', clientId: this.clientId });
  }

  /** Takes the lock naming this tab; the browser releases it when the tab dies. */
  private holdPresence(locks: LockManagerLike): Promise<void> {
    const held = new Promise<void>((resolve, reject) => {
      void locks
        .request(
          presenceLockName(this.clientId),
          { signal: this.presenceRequest.signal, mode: 'exclusive' },
          () => {
            resolve();
            return new Promise<void>((release) => {
              this.releasePresence = release;
            });
          }
        )
        .catch((error: unknown) => {
          this.presenceLost = asError(error);
          reject(this.presenceLost);
        });
    });
    // A broker re-observes this rejection; swallow the unobserved-rejection warn.
    held.catch(() => undefined);
    return held;
  }

  /**
   * A follower holds no keys and never receives the login secret — the leader's
   * engine already owns key derivation. Starting a follower is just awaiting a
   * live leader; the secret is scrubbed by its terminal owner (`EngineClient`),
   * never handed to this keyless transport.
   */
  start(): Promise<void> {
    if (this.terminalError) return Promise.reject(this.terminalError);
    return this.leaderReady;
  }

  command(command: CommandDescriptor, _transfer: Transferable[]): Promise<void> {
    // Command arguments name files and contacts, so they take the private port
    // rather than the origin-wide channel.
    return this.overPort<void>((requestId) => ({ type: 'cb:portCommand', requestId, command }));
  }

  beginWrite(target: WriteTarget, size: number): Promise<WriteHandle> {
    return this.write<WriteHandle>({ kind: 'beginWrite', target, size });
  }

  pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void> {
    // Moved, not cloned: the upload plaintext leaves this tab's heap for the
    // leader's rather than being copied into every same-origin context.
    return this.write<void>({ kind: 'pushChunk', handle, chunk }, [chunk]);
  }

  commitWrite(handle: WriteHandle): Promise<bigint> {
    return this.write<bigint>({ kind: 'commitWrite', handle });
  }

  abortWrite(handle: WriteHandle): Promise<void> {
    return this.write<void>({ kind: 'abortWrite', handle });
  }

  snapshot(folder: Uint8Array | null): Promise<SnapshotDescriptor> {
    return this.read<SnapshotDescriptor>({ kind: 'snapshot', folder });
  }

  siweChallenge(): Promise<string> {
    return this.read<string>({ kind: 'siweChallenge' });
  }

  download(node: Uint8Array): Promise<ArrayBuffer> {
    return this.read<ArrayBuffer>({ kind: 'download', node });
  }

  openContentStream(node: Uint8Array): Promise<StreamHandle> {
    return this.stream<StreamHandle>({ kind: 'openContentStream', node });
  }

  readStream(handle: StreamHandle, offset: number, length: number): Promise<ArrayBuffer> {
    return this.stream<ArrayBuffer>({ kind: 'readStream', handle, offset, length });
  }

  closeStream(handle: StreamHandle): Promise<void> {
    return this.stream<void>({ kind: 'closeStream', handle });
  }

  private read<T>(read: WireRead): Promise<T> {
    return this.overPort<T>((requestId) => ({ type: 'cb:portRead', requestId, read }));
  }

  private stream<T>(stream: WireStream): Promise<T> {
    return this.overPort<T>((requestId) => ({ type: 'cb:portStream', requestId, stream }));
  }

  private overPort<T>(
    build: (requestId: number) => PortRequest,
    transfer?: Transferable[]
  ): Promise<T> {
    return this.request<T, MessagePortLike>(
      this.ensurePort(),
      (requestId, port) => {
        port.postMessage(build(requestId), transfer);
      },
      transfer
    );
  }

  private ensurePort(): Promise<MessagePortLike> {
    if (this.portPromise) return this.portPromise;
    const attempt = this.brokerPort();
    this.portPromise = attempt;
    // A failed broker must not latch: the next read asks the leader again.
    attempt.catch(() => {
      if (this.portPromise === attempt) this.portPromise = null;
    });
    return attempt;
  }

  /**
   * Dials the address this leadership published and takes the port back. The
   * follower opens the channel itself, so nothing but its own dial can hand it a
   * port, and the leader's greeting must still carry the active leader's token.
   */
  private async brokerPort(): Promise<MessagePortLike> {
    await this.leaderReady;
    // Fenced from the leadership this brokerage started under, not from the one
    // in force when a read first asked for a port.
    const generation = this.portGeneration;
    if (this.closed) throw retryError();
    // Before the greeting, never after: a leader watching a presence name this
    // tab does not hold is granted at once and reclaims a live tab.
    await this.awaitPresence();
    const port = await this.courier.connect(await this.awaitHost());
    const release = this.bindPort(port);
    try {
      port.postMessage({ type: 'cb:portHello', clientId: this.clientId } satisfies PortRequest);
      await this.awaitAdoption();
      if (this.closed || generation !== this.portGeneration) throw retryError();
    } catch (error) {
      release();
      throw error;
    }
    this.releasePort = release;
    return port;
  }

  /**
   * Binds the port listener, which answers only once the leader has greeted:
   * until then this port has proved nothing and settles no request.
   */
  private bindPort(port: MessagePortLike): () => void {
    let adopted = false;
    const listener = (event: MessageEvent): void => {
      const data: unknown = event.data;
      if (typeof data !== 'object' || data === null) return;
      const message = data as PortResponse | { type?: unknown };
      if (message.type === 'cb:portReady') {
        const { token } = message as Extract<PortResponse, { type: 'cb:portReady' }>;
        if (adopted || !this.fromActiveLeader(token)) return;
        adopted = true;
        this.settleBrokerage?.();
        return;
      }
      if (!adopted) return;
      if (message.type === 'cb:portEvent') {
        const { event } = message as Extract<PortResponse, { type: 'cb:portEvent' }>;
        this.emit(event);
        return;
      }
      if (message.type === 'cb:portClosed') {
        this.dropPort(retryError());
        this.rejectPending(retryError());
        // The event stream is one-way, so nothing else would re-dial: without
        // this a dropped port silently ends it until the next request.
        void this.ensurePort().catch(() => undefined);
        return;
      }
      if (message.type !== 'cb:portResult') return;
      const result = message as Extract<PortResponse, { type: 'cb:portResult' }>;
      if (result.ok) this.settle(result.requestId, true, undefined, result.result);
      else this.settle(result.requestId, false, result.error, undefined, result.code);
    };
    port.addEventListener('message', listener);
    port.start?.();
    return () => {
      port.removeEventListener('message', listener);
      port.close();
    };
  }

  /** This tab's presence, under the brokerage timeout like every other step. */
  private awaitPresence(): Promise<void> {
    // A presence that was held and then lost must not latch resolved: greeting
    // on a name this tab no longer holds invites the leader to reclaim it live.
    if (this.presenceLost) return Promise.reject(this.presenceLost);
    return this.awaitBrokerage<void>('this tab holds no presence lock', (settle) => {
      void this.presenceHeld.then(settle, (error: unknown) =>
        this.abortBrokerage?.(asError(error))
      );
    });
  }

  /** Asks where this leadership takes follower ports, for this leadership only. */
  private awaitHost(): Promise<string> {
    return this.awaitBrokerage<string>('the leader published no port host', (settle) => {
      this.settleHost = settle;
      this.post({ type: 'cb:portWanted', clientId: this.clientId });
    });
  }

  /** The leader's proof it holds the far end, stamped with its leadership token. */
  private awaitAdoption(): Promise<void> {
    return this.awaitBrokerage<void>('the leader did not adopt the port', (settle) => {
      this.settleBrokerage = settle;
    });
  }

  /** One brokerage step: settled by the wire, by a timeout, or by `dropPort`. */
  private awaitBrokerage<T>(
    timeoutMessage: string,
    arm: (settle: (value: T) => void) => void
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const finish = (): void => {
        clearTimeout(timer);
        this.settleHost = null;
        this.settleBrokerage = null;
        this.abortBrokerage = null;
      };
      const timer = setTimeout(() => {
        finish();
        reject(new Error(timeoutMessage));
      }, this.portTimeoutMs);
      this.abortBrokerage = (error) => {
        finish();
        reject(error);
      };
      arm((value) => {
        finish();
        resolve(value);
      });
    });
  }

  /** Retires the port bound to a leadership this follower has left behind. */
  private dropPort(reason: Error): void {
    this.portGeneration += 1;
    this.portPromise = null;
    this.abortBrokerage?.(reason);
    const release = this.releasePort;
    this.releasePort = null;
    release?.();
  }

  private write<T>(write: WireWrite, transfer?: Transferable[]): Promise<T> {
    return this.overPort<T>((requestId) => ({ type: 'cb:portWrite', requestId, write }), transfer);
  }

  /**
   * Reports this tab's open folder to the leader's focus-window union. A folder
   * id names what the user is browsing, so it takes the port like every other
   * argument; a dropped hint costs staleness, never correctness.
   */
  reportFocus(node: Uint8Array | null): void {
    if (this.closed) return;
    void this.ensurePort()
      .then((port) => port.postMessage({ type: 'cb:portFocus', node } satisfies PortRequest))
      .catch(() => undefined);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    const error = new Error('engine transport closed');
    // Unblock a request parked on `leaderReady`, then reject all in-flight work.
    this.rejectLeaderReady(error);
    this.fail(error);
    this.dropPort(error);
    // Held → released; still queued → withdrawn.
    this.releasePresence?.();
    this.releasePresence = null;
    this.presenceRequest.abort();
    try {
      this.post({ type: 'cb:bye', clientId: this.clientId });
    } catch {
      // The channel may already be torn down; teardown proceeds regardless.
    }
    this.channel.removeEventListener('message', this.onMessage);
  }

  /** Every follower→leader channel post, so the union is a constraint, not a note. */
  private post(message: FollowerMessage): void {
    this.channel.postMessage(message);
  }

  private armLeaderReady(): void {
    this.leaderReady = new Promise<void>((resolve, reject) => {
      this.resolveLeaderReady = resolve;
      this.rejectLeaderReady = reject;
    });
    // A request re-observes this rejection; swallow the unobserved-rejection warn.
    this.leaderReady.catch(() => undefined);
  }

  private receive(data: unknown): void {
    if (this.closed || typeof data !== 'object' || data === null) return;
    const message = data as LeaderMessage | { type?: string };
    switch (message.type) {
      case 'cb:leader':
        this.onLeader((message as Extract<LeaderMessage, { type: 'cb:leader' }>).token);
        return;
      case 'cb:leaderGone':
        this.onLeaderGone((message as Extract<LeaderMessage, { type: 'cb:leaderGone' }>).token);
        return;
      case 'cb:portHost': {
        const host = message as Extract<LeaderMessage, { type: 'cb:portHost' }>;
        if (!this.fromActiveLeader(host.token) || typeof host.address !== 'string') return;
        this.settleHost?.(host.address);
        return;
      }
    }
  }

  private fromActiveLeader(token: string): boolean {
    return this.leaderToken !== null && token === this.leaderToken;
  }

  private onLeader(token: string): void {
    if (this.leaderToken === token) return; // duplicate beacon from the same leadership
    if (this.leaderToken !== null) {
      this.dropPort(retryError());
      // Leadership moved to a new tab without a graceful step-down (the old
      // leader crashed): reject requests bound to it so the UI retries the new
      // leader. New commands go to the new leader once the token is adopted.
      this.rejectPending(retryError());
      this.onLeadershipChange();
    }
    this.leaderToken = token;
    this.resolveLeaderReady();
    // Broker eagerly at the swap: the first read then costs no rendezvous.
    void this.ensurePort().catch(() => undefined);
  }

  private onLeaderGone(token: string): void {
    // Only the current leader may step us down; ignore a stale/forged farewell.
    if (this.leaderToken === null || token !== this.leaderToken) return;
    this.leaderToken = null;
    this.dropPort(retryError());
    this.rejectPending(retryError());
    this.onLeadershipChange();
    // Re-arm so subsequent commands await the next leader rather than resolving
    // against the departed one.
    this.armLeaderReady();
  }
}

function retryError(): Error {
  return new Error('leader changed; retry');
}
