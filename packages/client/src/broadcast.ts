/**
 * The cross-tab broadcast wire (blueprint/web-client.md "Followers are thin
 * mirrors"). Followers send commands to the leader and receive view projections
 * plus the one-way event stream back, all over a single `BroadcastChannel`.
 *
 * Security shape, structural not by discipline:
 * - The login **secret never crosses** — a follower scrubs it locally and lets
 *   the leader's already-started engine own key derivation.
 * - Leader → follower carries only key-free, plaintext-free `EventDescriptor`s
 *   (the facade's event surface exposes no key bytes by construction).
 * - Follower → leader commands may carry the user's own upload bytes as a
 *   `Blob` handle: structured clone shares the immutable backing store, so the
 *   cross-tab hop copies no bytes (blueprint "no byte copies for uploads").
 */

import type { CommandDescriptor, EventDescriptor } from './worker/protocol.js';

/** The subset of `BroadcastChannel` the transport/relay drive (injectable). */
export interface BroadcastChannelLike {
  postMessage(message: unknown): void;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  close(): void;
}

/**
 * A command on the wire. Binary upload content is hoisted out of the descriptor
 * into a `Blob` sibling so it rides as a shared handle, not a structured-clone
 * byte copy; the descriptor's own `content` field is nulled for transit.
 */
export interface WireCommand {
  command: CommandDescriptor;
  content?: Blob;
}

/** Follower → leader messages. */
export type FollowerMessage =
  /** A follower announces itself so the leader replies with a `leader` beacon. */
  | { type: 'cb:hello'; clientId: string }
  /** A correlated command; the leader answers with a matching `response`. */
  | { type: 'cb:command'; clientId: string; requestId: number; wire: WireCommand }
  /** This tab's currently open folder (for the leader's focus-window union). */
  | { type: 'cb:focus'; clientId: string; node: Uint8Array | null }
  /** A follower is leaving (tab close / transport teardown). */
  | { type: 'cb:bye'; clientId: string };

/** Leader → follower messages. */
export type LeaderMessage =
  /** The current leader announces itself (on election and on demand). */
  | { type: 'cb:leader' }
  /** The correlated result of a follower's command. */
  | { type: 'cb:response'; clientId: string; requestId: number; ok: true }
  | { type: 'cb:response'; clientId: string; requestId: number; ok: false; error: string }
  /** One engine event, fanned out to every follower in emission order. */
  | { type: 'cb:event'; event: EventDescriptor };

export type BroadcastMessage = FollowerMessage | LeaderMessage;

/** The channel name pairing the broadcast wire with the `cipherbox-engine` lock. */
export const BROADCAST_CHANNEL_NAME = 'cipherbox-engine';

/** A per-tab identity for command correlation. Injectable for deterministic tests. */
export function newClientId(): string {
  return globalThis.crypto.randomUUID();
}

/**
 * Hoists binary upload content out of a command descriptor into a shared `Blob`
 * handle. `create`/`updateContent` carry an `ArrayBuffer` the UI transferred in;
 * across the channel we wrap it once so followers copy no upload bytes.
 */
export function hoistContent(command: CommandDescriptor): WireCommand {
  // A 0-byte placeholder satisfies `updateContent`'s non-nullable field on the
  // wire; the real bytes ride the `Blob` and are re-attached by `lowerContent`.
  if (command.kind === 'create' && command.content) {
    return { command: { ...command, content: null }, content: new Blob([command.content]) };
  }
  if (command.kind === 'updateContent') {
    return { command: { ...command, content: EMPTY }, content: new Blob([command.content]) };
  }
  return { command };
}

const EMPTY = new ArrayBuffer(0);

/**
 * Rebuilds a leader-side command descriptor from the wire, reading the hoisted
 * `Blob` back into an `ArrayBuffer` that the leader transfers into its worker.
 */
export async function lowerContent(
  wire: WireCommand
): Promise<{ command: CommandDescriptor; transfer: Transferable[] }> {
  const { command, content } = wire;
  if (content && (command.kind === 'create' || command.kind === 'updateContent')) {
    const buffer = await content.arrayBuffer();
    return { command: { ...command, content: buffer }, transfer: [buffer] };
  }
  return { command, transfer: [] };
}
