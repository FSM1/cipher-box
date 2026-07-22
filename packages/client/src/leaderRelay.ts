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
 * No keys and no plaintext leave the worker: only key-free `EventDescriptor`s
 * ride the outbound wire, exactly the facade's event surface.
 */

import {
  lowerContent,
  type BroadcastChannelLike,
  type FollowerMessage,
  type LeaderMessage,
} from './broadcast.js';
import type { EngineTransport } from './transport.js';

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
  private readonly unsubscribe: () => void;
  private closed = false;
  // An unguessable per-leadership capability. It stamps every leader→follower
  // message so followers reject forged acks/events from a non-leader same-origin
  // context (integrity defense-in-depth; same-origin is the trust boundary).
  private readonly token = globalThis.crypto.randomUUID();
  private readonly onMessage = (event: MessageEvent): void => this.receive(event.data);

  constructor(
    private readonly channel: BroadcastChannelLike,
    private readonly transport: EngineTransport
  ) {
    this.channel.addEventListener('message', this.onMessage);
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
      case 'cb:focus': {
        const { clientId, node } = message as Extract<FollowerMessage, { type: 'cb:focus' }>;
        if (this.focus.set(clientId, node)) this.refreshHint();
        return;
      }
      case 'cb:bye': {
        const { clientId } = message as Extract<FollowerMessage, { type: 'cb:bye' }>;
        if (this.focus.remove(clientId)) this.refreshHint();
        return;
      }
    }
  }

  private async forward(message: Extract<FollowerMessage, { type: 'cb:command' }>): Promise<void> {
    const { clientId, requestId, wire } = message;
    try {
      const { command, transfer } = await lowerContent(wire);
      await this.transport.command(command, transfer);
      this.post({ type: 'cb:response', token: this.token, clientId, requestId, ok: true });
    } catch (error) {
      this.post({
        type: 'cb:response',
        token: this.token,
        clientId,
        requestId,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      });
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
