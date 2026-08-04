/**
 * The cross-tab broadcast wire (blueprint/web-client.md "Followers are thin
 * mirrors"). The `BroadcastChannel` carries election, the port rendezvous, and
 * the one-way event stream — nothing else. Every value-bearing exchange, in both
 * directions, rides the follower's private port ([`PortRequest`](PortRequest)):
 * command arguments and upload chunks up, snapshot projections and file
 * plaintext down. The channel exists to rendezvous that port.
 *
 * Security shape, structural not by discipline:
 * - The login **secret never crosses** — the keyless follower transport takes no
 *   secret at all (its `start` has no secret parameter); `EngineClient`, the
 *   secret's terminal owner, scrubs the buffer it chose not to use and lets the
 *   leader's already-started engine own key derivation.
 * - Leader → follower carries only key-free, plaintext-free `EventDescriptor`s
 *   (the facade's event surface exposes no key bytes by construction).
 * - A `BroadcastChannel` carries no transferables, so anything value-bearing put
 *   on it is cloned into every same-origin context that opened it. The port
 *   moves upload buffers instead, so a chunk's plaintext leaves the follower's
 *   heap rather than being copied to every bystander.
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
  /** Answers `cb:portPing`; the leader's proof this tab is still alive. */
  | { type: 'cb:portPong' }
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
 * durable op id.
 */
export type PortResponse =
  /** The leader adopted this port, naming the leadership that answers on it. */
  | { type: 'cb:portReady'; token: string }
  /** The leader is dropping this port. A closed `MessagePort` fires no event on
   * the far side, so without this a read would wait on a wire that is gone. */
  | { type: 'cb:portClosed' }
  /** Liveness probe: a port that stops answering has lost the tab behind it. */
  | { type: 'cb:portPing' }
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
  /** This tab's currently open folder (for the leader's focus-window union). */
  | { type: 'cb:focus'; clientId: string; node: Uint8Array | null }
  /** A follower is leaving (tab close / transport teardown). */
  | { type: 'cb:bye'; clientId: string };

/**
 * Leader → follower messages. Every one carries the current leadership's
 * `token` — an unguessable per-leadership capability minted at election. Same
 * origin is the trust boundary, but any same-origin context can post a forged
 * `cb:event` or `cb:portHost`; followers reject any leader message whose token
 * isn't the active leader's, so a non-leader cannot inject an event or divert
 * the port rendezvous.
 */
export type LeaderMessage =
  /** The current leader announces itself (on election and on demand). */
  | { type: 'cb:leader'; token: string }
  /** The current leader is stepping down (graceful teardown); re-arm the gate. */
  | { type: 'cb:leaderGone'; token: string }
  /** Where a follower may open its private port to this leadership. */
  | { type: 'cb:portHost'; token: string; address: string }
  /** One engine event, fanned out to every follower in emission order. */
  | { type: 'cb:event'; token: string; event: EventDescriptor };

export type BroadcastMessage = FollowerMessage | LeaderMessage;

/** The channel name pairing the broadcast wire with the `cipherbox-engine` lock. */
export const BROADCAST_CHANNEL_NAME = 'cipherbox-engine';

/** A per-tab identity for command correlation. Injectable for deterministic tests. */
export function newClientId(): string {
  return globalThis.crypto.randomUUID();
}
