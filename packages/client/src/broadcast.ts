/**
 * The cross-tab broadcast wire (blueprint/web-client.md "Followers are thin
 * mirrors"). The `BroadcastChannel` carries election and the port rendezvous —
 * nothing else. Every exchange that names or measures vault content, in either
 * direction, rides the follower's private port: command arguments and upload
 * chunks up, snapshot projections, file plaintext and the engine event stream
 * down. The channel exists to rendezvous that port.
 *
 * Security shape, structural not by discipline:
 * - The login **secret never crosses** — the keyless follower transport takes no
 *   secret at all (its `start` has no secret parameter); `EngineClient`, the
 *   secret's terminal owner, scrubs the buffer it chose not to use and lets the
 *   leader's already-started engine own key derivation.
 * - A `BroadcastChannel` carries no transferables, so anything value-bearing put
 *   on it is cloned into every same-origin context that opened it. The port
 *   moves upload buffers instead, so a chunk's plaintext leaves the follower's
 *   heap rather than being copied to every bystander.
 * - What a bystanding same-origin context sees on the channel, stated exactly:
 *   per-tab `clientId`s, the leadership token and the port-host address. No key
 *   bytes, no plaintext, no user-supplied names, and no node id, IPNS name,
 *   routing key or block count. Same origin remains the trust boundary.
 */

import type {
  CommandDescriptor,
  EventDescriptor,
  SnapshotDescriptor,
  StreamHandle,
  WriteHandle,
  WriteTarget,
} from './worker/protocol.js';

/** The subset of `BroadcastChannel` the transport/relay drive (injectable). */
export interface BroadcastChannelLike {
  postMessage(message: unknown): void;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  close(): void;
}

/** A follower read intent: served by the leader's engine, answered by value. */
export type WireRead =
  | { kind: 'snapshot'; folder: Uint8Array | null }
  | { kind: 'siweChallenge' }
  | { kind: 'download'; node: Uint8Array };

/** A follower ranged-read step, driven against the leader's engine stream. */
export type WireStream =
  | { kind: 'openContentStream'; node: Uint8Array }
  | { kind: 'readStream'; handle: StreamHandle; offset: number; length: number }
  | { kind: 'closeStream'; handle: StreamHandle };

/** A follower streaming-write step, driven against the leader's engine. */
export type WireWrite =
  | { kind: 'beginWrite'; target: WriteTarget; size: number }
  | { kind: 'pushChunk'; handle: WriteHandle; chunk: ArrayBuffer }
  | { kind: 'commitWrite'; handle: WriteHandle }
  | { kind: 'abortWrite'; handle: WriteHandle };

/**
 * Follower → leader, over that follower's private port. Everything carrying a
 * value rides here rather than on the channel: a `readStream` window *is*
 * plaintext, an upload chunk is plaintext, and a command's arguments name files
 * and contacts. Port ownership is self-asserted, so binding a handle to a client
 * is lifecycle bookkeeping, not authorization — same origin remains the trust
 * boundary.
 */
export type PortRequest =
  /** Names the sender, binding the port to a client the leader can reclaim it for. */
  | { type: 'cb:portHello'; clientId: string }
  /** This tab's currently open folder (for the leader's focus-window union). */
  | { type: 'cb:portFocus'; node: Uint8Array | null }
  /** A correlated read; the leader answers with a matching `cb:portResult`. */
  | { type: 'cb:portRead'; requestId: number; read: WireRead }
  /** A correlated ranged-read step, run against the leader's engine stream. */
  | { type: 'cb:portStream'; requestId: number; stream: WireStream }
  /** A correlated command, run against the leader's engine. */
  | { type: 'cb:portCommand'; requestId: number; command: CommandDescriptor }
  /** A correlated write step, run against the leader's engine write handle. */
  | { type: 'cb:portWrite'; requestId: number; write: WireWrite };

/**
 * Leader → follower, over that follower's private port. A `download` or
 * `readStream` result is the plaintext buffer itself, transferred rather than
 * cloned; a snapshot carries the descriptor; a SIWE challenge the nonce string;
 * `openContentStream` and `beginWrite` the handle they minted; `commitWrite` the
 * durable op id. Nothing here carries the leadership token but the adoption
 * itself: the port is private to one leadership, so holding the far end *is* the
 * proof the token stands in for on the channel.
 */
export type PortResponse =
  /** The leader adopted this port, naming the leadership that answers on it. */
  | { type: 'cb:portReady'; token: string }
  /** The leader is dropping this port. A closed `MessagePort` fires no event on
   * the far side, so without this a read would wait on a wire that is gone. */
  | { type: 'cb:portClosed' }
  /**
   * One engine event, fanned out to every adopted port in emission order. It
   * takes the port rather than the channel because its variants name nodes,
   * IPNS names and routing keys and count a version's blocks.
   */
  | { type: 'cb:portEvent'; event: EventDescriptor }
  | {
      type: 'cb:portResult';
      requestId: number;
      ok: true;
      result?: SnapshotDescriptor | ArrayBuffer | string | StreamHandle | WriteHandle;
    }
  | { type: 'cb:portResult'; requestId: number; ok: false; error: string; code?: string };

/** Follower → leader messages. */
export type FollowerMessage =
  /** A follower announces itself so the leader replies with a `leader` beacon. */
  | { type: 'cb:hello'; clientId: string }
  /** Asks the leader where a private port may be opened to it. */
  | { type: 'cb:portWanted'; clientId: string }
  /** A follower is leaving (tab close / transport teardown). */
  | { type: 'cb:bye'; clientId: string };

/**
 * Leader → follower messages. Every one carries the current leadership's
 * `token` — an unguessable per-leadership capability minted at election, which
 * followers check before acting on a beacon or a port rendezvous. The token is
 * itself broadcast, so it bounds accidental and passive delivery, never a
 * same-origin context that read the beacon: same origin is the trust boundary.
 */
export type LeaderMessage =
  /** The current leader announces itself (on election and on demand). */
  | { type: 'cb:leader'; token: string }
  /** The current leader is stepping down (graceful teardown); re-arm the gate. */
  | { type: 'cb:leaderGone'; token: string }
  /** Where a follower may open its private port to this leadership. */
  | { type: 'cb:portHost'; token: string; address: string };

export type BroadcastMessage = FollowerMessage | LeaderMessage;

/** The channel name pairing the broadcast wire with the `cipherbox-engine` lock. */
export const BROADCAST_CHANNEL_NAME = 'cipherbox-engine';

/**
 * The Web Lock a tab holds for its whole life, so the leader can watch for its
 * death: the browser releases it on close, crash or discard, and the leader's
 * queued request for the same name is granted at exactly that moment. Namespaced
 * away from the engine lock, which elects rather than reports presence.
 * `navigator.locks.query()` reads these names origin-wide, so a name carries a
 * `clientId` and nothing else — never a node id, a name or a count.
 */
export function presenceLockName(clientId: string): string {
  return `cipherbox-presence:${clientId}`;
}

/** A per-tab identity for command correlation. Injectable for deterministic tests. */
export function newClientId(): string {
  return globalThis.crypto.randomUUID();
}
