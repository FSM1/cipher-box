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
 */

import {
  type BroadcastChannelLike,
  type LeaderMessage,
  type WireRead,
  type WireWrite,
} from './broadcast.js';
import { CorrelatedTransport } from './correlatedTransport.js';
import type {
  CommandDescriptor,
  SnapshotDescriptor,
  WriteHandle,
  WriteTarget,
} from './worker/protocol.js';

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

  private readonly onMessage = (event: MessageEvent): void => this.receive(event.data);

  constructor(
    private readonly channel: BroadcastChannelLike,
    private readonly clientId: string
  ) {
    super();
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

  async download(node: Uint8Array): Promise<ArrayBuffer> {
    // The leader answers with a `Blob` handle (shared backing, no byte copy);
    // materialize the bytes only here, in the requesting follower.
    const content = await this.read<Blob>({ kind: 'download', node });
    return content.arrayBuffer();
  }

  private read<T>(read: WireRead): Promise<T> {
    return this.request<T>(this.leaderReady, (requestId) =>
      this.channel.postMessage({ type: 'cb:read', clientId: this.clientId, requestId, read })
    );
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
    this.rejectPending(retryError());
    // Re-arm so subsequent commands await the next leader rather than resolving
    // against the departed one.
    this.armLeaderReady();
  }
}

function retryError(): Error {
  return new Error('leader changed; retry');
}
