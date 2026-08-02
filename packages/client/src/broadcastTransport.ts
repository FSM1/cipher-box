/**
 * The follower-side `EngineTransport` (blueprint/web-client.md "Followers are
 * thin mirrors"). A non-leader tab holds no worker and no keys: it sends
 * commands as data to the leader over the `BroadcastChannel` and renders the
 * projections and events the leader broadcasts back.
 *
 * It honors the same teardown contract as `LocalTransport`: a torn-down or
 * leader-dead transport **rejects** every pending request, never hangs — so a
 * command caught in flight at a leadership swap surfaces a retry to the UI
 * rather than silently disappearing.
 *
 * A follower authenticates the leader by an unguessable per-leadership `token`
 * carried on the `cb:leader` beacon: it stamps every accepted response/event and
 * lets the follower reject forged acks/events from a non-leader same-origin
 * context.
 *
 * Reads take a different wire: the channel only rendezvouses a private
 * `MessagePort` to the leader, and every snapshot and plaintext window comes
 * back over that port, so no other same-origin context is a receiver.
 */

import {
  type BroadcastChannelLike,
  type LeaderMessage,
  type ReadPortRequest,
  type ReadPortResponse,
  type WireRead,
  type WireWrite,
} from './broadcast.js';
import { CorrelatedTransport } from './correlatedTransport.js';
import type { MessagePortLike } from './media/protocol.js';
import type { PortCourier } from './portCourier.js';
import type {
  CommandDescriptor,
  SnapshotDescriptor,
  WriteHandle,
  WriteTarget,
} from './worker/protocol.js';

/** How long a follower waits on each step of brokering its read port. */
const DEFAULT_PORT_TIMEOUT_MS = 5000;

/** A read awaits its port before it correlates, so its readiness gate is open. */
const OPEN_GATE = Promise.resolve();

export interface BroadcastTransportOptions {
  portTimeoutMs?: number;
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

  // The read port to the current leadership, re-brokered from scratch whenever
  // leadership moves. `portGeneration` fences a broker still in flight across
  // that move, so a read never lands on a port the departed leader served.
  private portPromise: Promise<MessagePortLike> | null = null;
  private releasePort: (() => void) | null = null;
  private portGeneration = 0;
  private readonly hostWaiters = new Set<(address: string) => void>();
  private readonly adoptionWaiters = new Set<(token: string) => void>();
  // Every parked brokerage step, so teardown and a leadership swap settle one
  // immediately instead of leaving a read to wait out its timeout.
  private readonly portWaits = new Set<(error: Error) => void>();
  private readonly portTimeoutMs: number;

  private readonly onMessage = (event: MessageEvent): void => this.receive(event.data);

  constructor(
    private readonly channel: BroadcastChannelLike,
    private readonly clientId: string,
    private readonly courier: PortCourier,
    options: BroadcastTransportOptions = {}
  ) {
    super();
    this.portTimeoutMs = options.portTimeoutMs ?? DEFAULT_PORT_TIMEOUT_MS;
    this.armLeaderReady();
    this.channel.addEventListener('message', this.onMessage);
    // Announce ourselves so a live leader replies with a `leader` beacon.
    this.channel.postMessage({ type: 'cb:hello', clientId: this.clientId });
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
    return this.dispatch(this.leaderReady, (requestId) =>
      this.channel.postMessage({ type: 'cb:command', clientId: this.clientId, requestId, command })
    );
  }

  beginWrite(target: WriteTarget, size: number): Promise<WriteHandle> {
    return this.write<WriteHandle>({ kind: 'beginWrite', target, size });
  }

  pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void> {
    // A `Blob` handle, not the buffer: structured clone shares its backing store
    // while an `ArrayBuffer` would be copied into every receiver.
    return this.write<void>({ kind: 'pushChunk', handle, chunk: new Blob([chunk]) });
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

  downloadRange(node: Uint8Array, offset: number, length: number): Promise<ArrayBuffer> {
    return this.read<ArrayBuffer>({ kind: 'downloadRange', node, offset, length });
  }

  private async read<T>(read: WireRead): Promise<T> {
    const port = await this.ensurePort();
    return this.request<T>(OPEN_GATE, (requestId) => {
      const request: ReadPortRequest = { type: 'cb:portRead', requestId, read };
      port.postMessage(request);
    });
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

  private async brokerPort(): Promise<MessagePortLike> {
    await this.leaderReady;
    const generation = this.portGeneration;
    const port = await this.courier.connect(await this.awaitHost());
    const listener = (event: MessageEvent): void => this.onPortMessage(event.data);
    port.addEventListener('message', listener);
    port.start?.();
    const release = (): void => {
      port.removeEventListener('message', listener);
      port.close();
    };
    try {
      const hello: ReadPortRequest = { type: 'cb:portHello', clientId: this.clientId };
      port.postMessage(hello);
      await this.awaitAdoption();
      if (this.closed || generation !== this.portGeneration) throw retryError();
    } catch (error) {
      release();
      throw error;
    }
    this.releasePort = release;
    return port;
  }

  /** Asks the leader where its read ports are taken, for this leadership only. */
  private awaitHost(): Promise<string> {
    return this.awaitAnswer(this.hostWaiters, 'the leader published no read port host', () =>
      this.channel.postMessage({ type: 'cb:portWanted', clientId: this.clientId })
    );
  }

  /** The leader's proof it holds the far end, stamped with its leadership token. */
  private awaitAdoption(): Promise<string> {
    return this.awaitAnswer(this.adoptionWaiters, 'the leader did not adopt the read port');
  }

  private awaitAnswer<T>(
    waiters: Set<(value: T) => void>,
    timeoutMessage: string,
    ask?: () => void
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const finish = (): void => {
        clearTimeout(timer);
        waiters.delete(waiter);
        this.portWaits.delete(abort);
      };
      const waiter = (value: T): void => {
        finish();
        resolve(value);
      };
      const abort = (error: Error): void => {
        finish();
        reject(error);
      };
      const timer = setTimeout(() => abort(new Error(timeoutMessage)), this.portTimeoutMs);
      waiters.add(waiter);
      this.portWaits.add(abort);
      ask?.();
    });
  }

  /** The port is point-to-point, so only its adoption carries a token check. */
  private onPortMessage(data: unknown): void {
    if (this.closed) return;
    const message = data as ReadPortResponse | { type?: unknown };
    if (message.type === 'cb:portReady') {
      const { token } = message as Extract<ReadPortResponse, { type: 'cb:portReady' }>;
      if (!this.fromActiveLeader(token)) return;
      for (const waiter of [...this.adoptionWaiters]) waiter(token);
      return;
    }
    if (message.type !== 'cb:portResult') return;
    const result = message as Extract<ReadPortResponse, { type: 'cb:portResult' }>;
    if (result.ok) this.settle(result.requestId, true, undefined, result.result);
    else this.settle(result.requestId, false, result.error, undefined, result.code);
  }

  /** Retires the port bound to a leadership this follower has left behind. */
  private dropPort(reason: Error): void {
    this.portGeneration += 1;
    this.portPromise = null;
    for (const abort of [...this.portWaits]) abort(reason);
    const release = this.releasePort;
    this.releasePort = null;
    release?.();
  }

  private write<T>(write: WireWrite): Promise<T> {
    return this.request<T>(this.leaderReady, (requestId) =>
      this.channel.postMessage({ type: 'cb:write', clientId: this.clientId, requestId, write })
    );
  }

  /** Reports this tab's open folder to the leader's focus-window union. */
  reportFocus(node: Uint8Array | null): void {
    if (this.closed) return;
    this.channel.postMessage({ type: 'cb:focus', clientId: this.clientId, node });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    const error = new Error('engine transport closed');
    // Unblock a request parked on `leaderReady`, then reject all in-flight work.
    this.rejectLeaderReady(error);
    this.fail(error);
    this.dropPort(error);
    try {
      this.channel.postMessage({ type: 'cb:bye', clientId: this.clientId });
    } catch {
      // The channel may already be torn down; teardown proceeds regardless.
    }
    this.channel.removeEventListener('message', this.onMessage);
  }

  private armLeaderReady(): void {
    this.leaderReady = new Promise<void>((resolve, reject) => {
      this.resolveLeaderReady = resolve;
      this.rejectLeaderReady = reject;
    });
    // A request re-observes this rejection; swallow the unobserved-rejection warn.
    this.leaderReady.catch(() => undefined);
  }

  private receive(message: LeaderMessage | { type?: string }): void {
    if (this.closed) return;
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
        for (const waiter of [...this.hostWaiters]) waiter(host.address);
        return;
      }
      case 'cb:response': {
        const response = message as Extract<LeaderMessage, { type: 'cb:response' }>;
        if (response.clientId !== this.clientId) return;
        if (!this.fromActiveLeader(response.token)) return; // forged / stale ack
        if (response.ok) {
          this.settle(response.requestId, true, undefined, response.result);
        } else {
          this.settle(response.requestId, false, response.error, undefined, response.code);
        }
        return;
      }
      case 'cb:event': {
        const event = message as Extract<LeaderMessage, { type: 'cb:event' }>;
        if (!this.fromActiveLeader(event.token)) return; // forged / stale event
        this.emit(event.event);
        return;
      }
    }
  }

  private fromActiveLeader(token: string): boolean {
    return this.leaderToken !== null && token === this.leaderToken;
  }

  private onLeader(token: string): void {
    if (this.leaderToken === token) return; // duplicate beacon from the same leadership
    this.dropPort(retryError());
    if (this.leaderToken !== null) {
      // Leadership moved to a new tab without a graceful step-down (the old
      // leader crashed): reject requests bound to it so the UI retries the new
      // leader. New commands go to the new leader once the token is adopted.
      this.rejectPending(retryError());
    }
    this.leaderToken = token;
    this.resolveLeaderReady();
  }

  private onLeaderGone(token: string): void {
    // Only the current leader may step us down; ignore a stale/forged farewell.
    if (this.leaderToken === null || token !== this.leaderToken) return;
    this.leaderToken = null;
    this.dropPort(retryError());
    this.rejectPending(retryError());
    // Re-arm so subsequent commands await the next leader rather than resolving
    // against the departed one.
    this.armLeaderReady();
  }
}

function retryError(): Error {
  return new Error('leader changed; retry');
}
