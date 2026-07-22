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
import type { EngineEventListener, EngineTransport } from './transport.js';
import type { CommandDescriptor } from './worker/protocol.js';

interface Pending {
  resolve: () => void;
  reject: (error: Error) => void;
}

export class BroadcastTransport implements EngineTransport {
  private readonly pending = new Map<number, Pending>();
  private readonly listeners = new Set<EngineEventListener>();
  private nextId = 1;
  private closed = false;
  private terminalError: Error | null = null;

  private leaderPresent = false;
  private readonly leaderReady: Promise<void>;
  private resolveLeaderReady!: () => void;
  private rejectLeaderReady!: (error: Error) => void;

  private readonly onMessage = (event: MessageEvent): void => this.receive(event.data);

  constructor(
    private readonly channel: BroadcastChannelLike,
    private readonly clientId: string
  ) {
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
   * owns key derivation. Scrub this tab's copy and resolve once a leader is
   * confirmed present.
   */
  start(secret: ArrayBuffer): Promise<void> {
    new Uint8Array(secret).fill(0);
    if (this.terminalError) return Promise.reject(this.terminalError);
    return this.leaderReady;
  }

  command(command: CommandDescriptor, _transfer: Transferable[]): Promise<void> {
    if (this.terminalError) return Promise.reject(this.terminalError);
    return this.leaderReady.then(
      () =>
        new Promise<void>((resolve, reject) => {
          if (this.terminalError) {
            reject(this.terminalError);
            return;
          }
          const requestId = this.nextId++;
          this.pending.set(requestId, { resolve, reject });
          try {
            this.channel.postMessage({
              type: 'cb:command',
              clientId: this.clientId,
              requestId,
              wire: hoistContent(command),
            });
          } catch (error) {
            this.pending.delete(requestId);
            reject(error instanceof Error ? error : new Error(String(error)));
          }
        })
    );
  }

  subscribe(listener: EngineEventListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
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
        const pending = this.pending.get(response.requestId);
        if (!pending) return;
        this.pending.delete(response.requestId);
        if (response.ok) pending.resolve();
        else pending.reject(new Error(response.error));
        return;
      }
      case 'cb:event': {
        const { event } = message as Extract<LeaderMessage, { type: 'cb:event' }>;
        for (const listener of this.listeners) {
          try {
            listener(event);
          } catch {
            // One throwing subscriber must not drop the event for the rest.
          }
        }
        return;
      }
    }
  }

  private fail(error: Error): void {
    this.terminalError ??= error;
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
  }
}
