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

import type { BroadcastChannelLike, FollowerMessage, LeaderMessage } from './broadcast.js';
import { EngineRequestError } from './correlatedTransport.js';
import type { EngineTransport } from './transport.js';
import type { WriteHandle } from './worker/protocol.js';
import { WriteQueue } from './writeQueue.js';

/** The correlated ack envelope addressing one follower request. */
type Ack = { type: 'cb:response'; token: string; clientId: string; requestId: number };

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
    this.releaseWrites(null);
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
      case 'cb:read':
        void this.serveRead(message as Extract<FollowerMessage, { type: 'cb:read' }>);
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

  private async serveRead(message: Extract<FollowerMessage, { type: 'cb:read' }>): Promise<void> {
    const { clientId, requestId, read } = message;
    const ack = { type: 'cb:response', token: this.token, clientId, requestId } as const;
    try {
      if (read.kind === 'snapshot') {
        const result = await this.transport.snapshot(read.folder);
        this.post({ ...ack, ok: true, result });
      } else {
        // Wrap the plaintext in a `Blob` so the per-receiver structured clone
        // shares the immutable backing store instead of copying the bytes.
        const bytes = await this.transport.download(read.node);
        this.post({ ...ack, ok: true, result: new Blob([bytes]) });
      }
    } catch (error) {
      this.post({ ...ack, ok: false, ...wireError(error) });
    }
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
            this.writeOwners.delete(handle);
            return this.transport.abortWrite(handle);
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
