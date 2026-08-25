/**
 * The UI ↔ engine-worker wire protocol (blueprint/web-client.md "Engine hosting
 * and tab leadership").
 *
 * Everything here is plain structured-clone data. A wasm-bindgen `Command` wraps
 * a pointer into the worker's WASM memory and cannot cross a realm boundary, so
 * the UI sends a **command descriptor** — the facade's write intent as data —
 * and the worker rebuilds the real `Command` from it (`commandCodec`). This is a
 * wire format, not the forbidden TS mirror of engine *view* structures
 * (blueprint/web-client.md "Types are generated, not hand-mirrored"): it carries
 * only intent the engine already owns, never snapshot/view state, and never key
 * material — a grant carries the recipient's *public* identity key only.
 *
 * `u64`s cross as `bigint`; binary payloads cross as `Uint8Array`, with file
 * content transferred as an `ArrayBuffer` so no bytes are copied through the
 * boundary (blueprint/web-client.md "Boundary hygiene"). Content never rides a
 * command: it streams chunk by chunk through a write handle.
 */

import { isBuffer } from '../buffers.js';

/** Grant permission level (mirrors the facade `Permission`). */
export type Permission = 'read' | 'write';

/** What a created node is (mirrors the facade `NodeKind`). */
export type NodeKind = 'file' | 'folder';

/** The staleness ladder (mirrors the facade `Staleness`). */
export type Staleness = 'fresh' | 'reconciling' | 'stale' | 'offline';

/**
 * The phase an `opProgress` event reports (mirrors the facade `OpPhase`).
 * `uploadCompleted` means the version's blocks are on the network, not that its
 * record published — the op leaves the pending-op overlay when it does.
 */
export type OpProgressPhase =
  | 'downloadStarted'
  | 'downloadCompleted'
  | 'downloadFailed'
  | 'uploadStarted'
  | 'uploadProgress'
  | 'uploadCompleted'
  | 'uploadFailed'
  | 'uploadCancelled'
  | 'externalPinFailed';

/** One ancestor step in a snapshot's breadcrumb trail, as data. */
export interface BreadcrumbDescriptor {
  id: Uint8Array;
  name: string;
}

/** What the op queue holds for a node (mirrors the facade `PendingClass`). */
export type PendingClass = 'none' | 'metadata' | 'content';

/** Why a queued op will never publish (mirrors the facade `DeadLetterReason`). */
export type DeadLetterReason =
  | 'targetGone'
  | 'destinationGone'
  | 'destinationInsideTarget'
  | 'suffixExhausted'
  | 'undecodable'
  | 'payloadRefused'
  | 'attemptsExhausted'
  | 'contentUnrecoverable'
  | 'baseSuperseded'
  | 'headTooLarge';

/** A terminal dead-lettered op and its reason, as data. */
export interface DeadLetterDescriptor {
  opId: bigint;
  reason: DeadLetterReason;
}

/** The drain's over-budget hold, as data (mirrors the facade `BlockedOp`). */
export interface BlockedOpDescriptor {
  opId: bigint;
  node: Uint8Array;
  neededBytes: bigint;
}

/**
 * One direct child in a snapshot, as data. `size`/`mtime`/`contentVersion` are
 * `null` until projected.
 */
export interface SnapshotChildDescriptor {
  id: Uint8Array;
  name: string;
  kind: NodeKind;
  size: bigint | null;
  mtime: bigint | null;
  pending: PendingClass;
  deadLetter: boolean;
  contentVersion: bigint | null;
}

/**
 * A key-free folder snapshot, as data (mirrors the facade `SnapshotView`).
 * A wire projection of view state the engine owns, not the forbidden
 * hand-mirrored type surface — the wasm-bindgen `.d.ts` stays the contract.
 */
export interface SnapshotDescriptor {
  root: Uint8Array;
  folder: Uint8Array;
  /** The listed folder's own name, empty at the root. */
  folderName: string;
  children: SnapshotChildDescriptor[];
  ancestors: BreadcrumbDescriptor[];
  deadLetters: DeadLetterDescriptor[];
  /** The drain's over-budget hold, or `null` when nothing is held. */
  blocked: BlockedOpDescriptor | null;
  /**
   * Durable queue entries this session holds but cannot read — another
   * identity's, or written by a newer build. They occupy staged bytes against
   * the same device budget, so a host reports them rather than leaving an
   * over-budget rejection unexplained on a vault that looks empty.
   */
  retainedRecords: number;
  staleness: Staleness;
}

/** One contact the vault's book holds, as data (mirrors `SharingContact`). */
export interface SharingContactDescriptor {
  identityPublicKey: Uint8Array;
  encryptionPublicKey: Uint8Array;
}

/** One grant a scope's ledger commits, as data (mirrors `SharingGrant`). */
export interface SharingGrantDescriptor {
  /**
   * Joins the row to a contact by identity key. All-zero for a row the owner
   * could not vouch for, which joins to no contact.
   */
  recipientIdentityPublicKey: Uint8Array;
  permission: Permission;
  /**
   * Advisory expiry in Unix millis, `null` when the row carries none. Not a
   * capability boundary — no owner signature covers it.
   */
  expiresAt: bigint | null;
}

/**
 * One scope's sharing state, as data (mirrors the facade `SharingView`).
 * A wire projection of view state the engine owns, not the forbidden
 * hand-mirrored type surface — the wasm-bindgen `.d.ts` stays the contract.
 */
export interface SharingDescriptor {
  scope: Uint8Array;
  /** This vault's whole contact book, re-verified from each stored code. */
  contacts: SharingContactDescriptor[];
  /** Empty for a node that is not a scope root — nothing is granted there. */
  grants: SharingGrantDescriptor[];
}

/** Where a version's bytes are pinned (mirrors the facade `PinMode`). */
export type PinMode = 'hosted' | 'external' | 'dual';

/** The kind of member-supplied IPFS provider (mirrors the facade `ByoKind`). */
export type ByoKind = 'kubo' | 'psa' | 'pinata';

/** A member's own IPFS provider, as data. */
export interface ByoIpfsConfigDescriptor {
  endpoint: string;
  kind: ByoKind;
  /**
   * Bearer credential, `null` for a provider that needs none. A transferable
   * buffer rather than a string, which cannot be overwritten: every hop moves
   * it ([`commandTransfer`]), so the receiving realm is the only holder left
   * and is the terminal owner that scrubs it.
   */
  accessToken: ArrayBuffer | null;
}

/** The member's placement, provider and retention choice, as data. */
export interface VaultSettingsDescriptor {
  pinMode: PinMode;
  byo: ByoIpfsConfigDescriptor | null;
  /** Newest-n retention; `null` keeps every version within quota. */
  keepLatestVersions: number | null;
}

/**
 * One write intent, as data. Each variant's `kind` matches the facade command
 * builder name (`crates/wasm` `Command`), so the worker maps it mechanically.
 */
export type CommandDescriptor =
  | { kind: 'create'; parent: Uint8Array; name: string; nodeKind: NodeKind }
  | { kind: 'delete'; node: Uint8Array }
  | { kind: 'rename'; node: Uint8Array; newName: string }
  | { kind: 'relink'; node: Uint8Array; newParent: Uint8Array }
  | { kind: 'cancelUpload'; opId: bigint }
  | { kind: 'setFocus'; node: Uint8Array | null }
  | { kind: 'manualRefresh' }
  | { kind: 'importContact'; contactCode: Uint8Array }
  | {
      kind: 'grant';
      node: Uint8Array;
      recipientIdentityPublicKey: Uint8Array;
      permission: Permission;
    }
  | { kind: 'revoke'; node: Uint8Array; recipientIdentityPublicKey: Uint8Array }
  | { kind: 'downgrade'; node: Uint8Array; recipientIdentityPublicKey: Uint8Array }
  | { kind: 'createInviteLink'; node: Uint8Array; permission: Permission }
  | { kind: 'acceptShare'; sealedSharePointer: Uint8Array }
  | { kind: 'rotateNow'; node: Uint8Array }
  | { kind: 'saveVaultSettings'; settings: VaultSettingsDescriptor }
  | { kind: 'siweLogin'; message: string; signature: Uint8Array }
  | { kind: 'logout' };

/**
 * The buffers a command descriptor owns, for the `transfer` list of the send
 * that carries it. A transfer detaches the sender, so the credential inside a
 * settings command exists in exactly one realm at a time and its receiver is
 * the terminal owner that scrubs it (AGENTS.md 7); a clone would leave an
 * unwiped copy at every hop.
 *
 * Reads the bearer by shape rather than by `kind`, so a descriptor this build
 * cannot serve still loses its credential on the route that drops it, and takes
 * it unvalidated: a relay reads one off an untrusted port.
 */
export function commandTransfer(command: unknown): Transferable[] {
  const token = (
    command as { settings?: { byo?: { accessToken?: unknown } | null } | null } | null | undefined
  )?.settings?.byo?.accessToken;
  return isBuffer(token) ? [token] : [];
}

/**
 * What one command produced, as data (mirrors the facade `CommandOutcome`).
 *
 * `queued` carries the durable queue id a later `opProgress`/`deadLetter`
 * repeats, so a host correlates the call to the events it makes. Holding an
 * imported contact's keys is the proof its binding signature verified — the
 * engine has no other way to hand that evidence out.
 */
export type CommandOutcomeDescriptor =
  | { kind: 'done' }
  | { kind: 'queued'; opId: bigint }
  | { kind: 'contactImported'; identityPublicKey: Uint8Array; encPublicKey: Uint8Array };

/**
 * Where a streaming write lands: a new file named `name` under `parent`, or a
 * new version of the existing file `node`. Never both (the engine rejects it).
 */
export type WriteTarget = { parent: Uint8Array; name: string } | { node: Uint8Array };

/** An open write handle's id — the engine's `u64`, opaque to this layer. */
export type WriteHandle = bigint;

/**
 * An open read stream's id — the engine's `u64`, opaque to this layer. The
 * stream pins one content version, so every window read against the handle is a
 * slice of one authenticated object.
 */
export type StreamHandle = bigint;

/** One event the engine emitted, as data (mirrors the facade `Event`). */
export type EventDescriptor =
  | { kind: 'snapshotUpdated' }
  | { kind: 'stalenessChanged'; staleness: Staleness }
  | { kind: 'withheldUpdateEscalation'; ipnsName: Uint8Array }
  | { kind: 'deadLetter'; opId: bigint; reason: DeadLetterReason }
  | { kind: 'attributableAbuse'; description: string }
  | { kind: 'renewalFailed'; routingKey: string; detail: string }
  | { kind: 'vaultUnprovisioned'; retryable: boolean; detail: string }
  | {
      kind: 'opProgress';
      opId: bigint | null;
      node: Uint8Array;
      phase: OpProgressPhase;
      /**
       * Blocks of the version confirmed so far and its whole block count, on
       * the phases that count them.
       */
      blocksConfirmed: number | null;
      blocksTotal: number | null;
      error: string | null;
    };

/** A UI → worker request. `id` correlates the eventual response. */
export type WorkerRequest =
  | { type: 'start'; id: number; secret: ArrayBuffer; accountId: string }
  | { type: 'command'; id: number; command: CommandDescriptor }
  | { type: 'beginWrite'; id: number; target: WriteTarget; size: number }
  | { type: 'pushChunk'; id: number; handle: WriteHandle; chunk: ArrayBuffer }
  | { type: 'commitWrite'; id: number; handle: WriteHandle }
  | { type: 'abortWrite'; id: number; handle: WriteHandle }
  | { type: 'snapshot'; id: number; folder: Uint8Array | null }
  | { type: 'sharing'; id: number; scope: Uint8Array | null }
  | { type: 'siweChallenge'; id: number }
  | { type: 'download'; id: number; node: Uint8Array }
  | { type: 'openContentStream'; id: number; node: Uint8Array }
  | { type: 'readStream'; id: number; handle: StreamHandle; offset: number; length: number }
  | { type: 'closeStream'; id: number; handle: StreamHandle };

/** A worker → UI message. */
export type WorkerMessage =
  /** The worker has instantiated the engine and is ready for requests. */
  | { type: 'ready' }
  /**
   * The correlated result of a request. A value-bearing ok response carries it:
   * a `SnapshotDescriptor` for `snapshot`, a `SharingDescriptor` for `sharing`,
   * the plaintext `ArrayBuffer`
   * (transferred, not copied) for `download`/`readStream`, the nonce string
   * for `siweChallenge`, the write handle for `beginWrite`, the stream handle
   * for `openContentStream`, the durable op id for `commitWrite`, the outcome
   * for `command`.
   */
  | {
      type: 'response';
      id: number;
      ok: true;
      result?:
        | SnapshotDescriptor
        | SharingDescriptor
        | CommandOutcomeDescriptor
        | ArrayBuffer
        | bigint
        | string;
    }
  /**
   * A failed request. `error` is the human-readable diagnostic; `code` is the
   * engine's stable machine-readable error code (the wasm host's camelCase
   * `EngineError` variant name) when the failure came from the engine.
   */
  | { type: 'response'; id: number; ok: false; error: string; code?: string }
  /** One engine event, in emission order. */
  | { type: 'event'; event: EventDescriptor }
  /** Construction or event-pump failure; the worker is unusable. */
  | { type: 'fatal'; error: string };
