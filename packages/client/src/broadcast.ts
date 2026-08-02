/**
 * The cross-tab broadcast wire (blueprint/web-client.md "Followers are thin
 * mirrors"). Followers send commands to the leader and receive view projections
 * plus the one-way event stream back, all over a single `BroadcastChannel`.
 *
 * Security shape, structural not by discipline:
 * - The login **secret never crosses** — the keyless follower transport takes no
 *   secret at all (its `start` has no secret parameter); `EngineClient`, the
 *   secret's terminal owner, scrubs the buffer it chose not to use and lets the
 *   leader's already-started engine own key derivation.
 * - Leader → follower carries only key-free, plaintext-free `EventDescriptor`s
 *   (the facade's event surface exposes no key bytes by construction).
 * - Follower → leader upload chunks ride as a `Blob` handle: structured clone
 *   shares the immutable backing store, so the cross-tab hop copies no bytes
 *   (blueprint "no byte copies for uploads"). Transferables do not cross a
 *   `BroadcastChannel`, so a raw `ArrayBuffer` would be a full copy instead.
 */

import type {
  CommandDescriptor,
  EventDescriptor,
  SnapshotDescriptor,
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
  | { kind: 'download'; node: Uint8Array }
  | { kind: 'downloadRange'; node: Uint8Array; offset: number; length: number };

/** A follower streaming-write step, driven against the leader's engine. */
export type WireWrite =
  | { kind: 'beginWrite'; target: WriteTarget; size: number }
  | { kind: 'pushChunk'; handle: WriteHandle; chunk: Blob }
  | { kind: 'commitWrite'; handle: WriteHandle }
  | { kind: 'abortWrite'; handle: WriteHandle };

/** Follower → leader messages. */
export type FollowerMessage =
  /** A follower announces itself so the leader replies with a `leader` beacon. */
  | { type: 'cb:hello'; clientId: string }
  /** A correlated command; the leader answers with a matching `response`. */
  | { type: 'cb:command'; clientId: string; requestId: number; command: CommandDescriptor }
  /** A correlated read; the leader answers with a value-bearing `response`. */
  | { type: 'cb:read'; clientId: string; requestId: number; read: WireRead }
  /** A correlated write step, run against the leader's engine write handle. */
  | { type: 'cb:write'; clientId: string; requestId: number; write: WireWrite }
  /** This tab's currently open folder (for the leader's focus-window union). */
  | { type: 'cb:focus'; clientId: string; node: Uint8Array | null }
  /** A follower is leaving (tab close / transport teardown). */
  | { type: 'cb:bye'; clientId: string };

/**
 * Leader → follower messages. Every one carries the current leadership's
 * `token` — an unguessable per-leadership capability minted at election. Same
 * origin is the trust boundary, but any same-origin context can observe a
 * follower's `clientId`/`requestId` and post a forged `cb:response`/`cb:event`;
 * followers reject any leader message whose token isn't the active leader's, so
 * a non-leader cannot forge an ack or inject an event.
 */
export type LeaderMessage =
  /** The current leader announces itself (on election and on demand). */
  | { type: 'cb:leader'; token: string }
  /** The current leader is stepping down (graceful teardown); re-arm the gate. */
  | { type: 'cb:leaderGone'; token: string }
  /**
   * The correlated result of a follower's command, read, or write step. A
   * snapshot read's ok carries the descriptor in `result`; a plaintext read
   * carries a `Blob`; a SIWE challenge carries the nonce string;
   * `beginWrite`/`commitWrite` carry the handle / durable op id.
   */
  | {
      type: 'cb:response';
      token: string;
      clientId: string;
      requestId: number;
      ok: true;
      result?: SnapshotDescriptor | Blob | bigint | string;
    }
  /**
   * A failed command/read. `error` is the human-readable diagnostic; `code` is
   * the engine's stable machine-readable error code when the failure came from
   * the engine.
   */
  | {
      type: 'cb:response';
      token: string;
      clientId: string;
      requestId: number;
      ok: false;
      error: string;
      code?: string;
    }
  /** One engine event, fanned out to every follower in emission order. */
  | { type: 'cb:event'; token: string; event: EventDescriptor };

export type BroadcastMessage = FollowerMessage | LeaderMessage;

/** The channel name pairing the broadcast wire with the `cipherbox-engine` lock. */
export const BROADCAST_CHANNEL_NAME = 'cipherbox-engine';

/** A per-tab identity for command correlation. Injectable for deterministic tests. */
export function newClientId(): string {
  return globalThis.crypto.randomUUID();
}
