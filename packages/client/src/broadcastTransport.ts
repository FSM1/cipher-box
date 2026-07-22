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
 */

import { hoistContent, type BroadcastChannelLike, type LeaderMessage } from './broadcast.js';
import { CorrelatedTransport } from './correlatedTransport.js';
import type { CommandDescriptor } from './worker/protocol.js';

export class BroadcastTransport extends CorrelatedTransport {
  private closed = false;

  private leaderPresent = false;
  private readonly leaderReady: Promise<void>;
  private resolveLeaderReady!: () => void;
  private rejectLeaderReady!: (error: Error) => void;

  private readonly onMessage = (event: MessageEvent): void => this.receive(event.data);

  constructor(
    private readonly channel: BroadcastChannelLike,
    private readonly clientId: string
  ) {
    super();
    this.leaderReady = new Promise<void>((resolve, reject) => {
      this.resolveLeaderReady = resolve;
      this.rejectLeaderReady = reject;
    });
    this.leaderReady.catch(() => undefined);
    this.channel.addEventListener('message', this.onMessage);
    // Announce ourselves so a live leader replies with a `leader` beacon.
    this.channel.postMessage({ type: 'cb:hello', clientId: this.clientId });
  }

  /**
   * A follower never transmits the login secret — the leader's engine already
   * owns key derivation. This **consumes and scrubs** the secret: it zeroes the
   * caller's buffer so the plaintext never lingers in the keyless follower realm.
   * A caller MUST re-derive a fresh buffer via `SecretSource` for any retry
   * (e.g. failover cold-start) — never reuse this buffer, whose bytes are now 0.
   */
  start(secret: ArrayBuffer): Promise<void> {
    new Uint8Array(secret).fill(0);
    if (this.terminalError) return Promise.reject(this.terminalError);
    return this.leaderReady;
  }

  command(command: CommandDescriptor, _transfer: Transferable[]): Promise<void> {
    return this.dispatch(this.leaderReady, (requestId) =>
      this.channel.postMessage({
        type: 'cb:command',
        clientId: this.clientId,
        requestId,
        wire: hoistContent(command),
      })
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

  private receive(message: LeaderMessage | { type?: string }): void {
    switch (message.type) {
      case 'cb:leader':
        if (!this.leaderPresent) {
          this.leaderPresent = true;
          this.resolveLeaderReady();
        }
        return;
      case 'cb:response': {
        const response = message as Extract<LeaderMessage, { type: 'cb:response' }>;
        if (response.clientId !== this.clientId) return;
        this.settle(response.requestId, response.ok, response.ok ? undefined : response.error);
        return;
      }
      case 'cb:event': {
        const { event } = message as Extract<LeaderMessage, { type: 'cb:event' }>;
        this.emit(event);
        return;
      }
    }
  }
}
