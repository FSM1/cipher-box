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
 * boundary (blueprint/web-client.md "Boundary hygiene").
 */

/** Grant permission level (mirrors the facade `Permission`). */
export type Permission = 'read' | 'write';

/** What a created node is (mirrors the facade `NodeKind`). */
export type NodeKind = 'file' | 'folder';

/** The staleness ladder (mirrors the facade `Staleness`). */
export type Staleness = 'fresh' | 'reconciling' | 'stale' | 'offline';

/** The phase an `opProgress` event reports (mirrors the facade `OpPhase`). */
export type OpProgressPhase = 'downloadStarted' | 'downloadCompleted' | 'downloadFailed';

/** One ancestor step in a snapshot's breadcrumb trail, as data. */
export interface BreadcrumbDescriptor {
  id: Uint8Array;
  name: string;
}

/** One direct child in a snapshot, as data. `size`/`mtime` are `null` until projected. */
export interface SnapshotChildDescriptor {
  id: Uint8Array;
  name: string;
  kind: NodeKind;
  size: bigint | null;
  mtime: bigint | null;
  pending: boolean;
  deadLetter: boolean;
  contentVersion: bigint;
}

/**
 * A key-free folder snapshot, as data (mirrors the facade `SnapshotView`).
 * A wire projection of view state the engine owns, not the forbidden
 * hand-mirrored type surface — the wasm-bindgen `.d.ts` stays the contract.
 */
export interface SnapshotDescriptor {
  root: Uint8Array;
  folder: Uint8Array;
  children: SnapshotChildDescriptor[];
  ancestors: BreadcrumbDescriptor[];
  deadLetters: bigint[];
  staleness: Staleness;
}

/**
 * One write intent, as data. Each variant's `kind` matches the facade command
 * builder name (`crates/wasm` `Command`), so the worker maps it mechanically.
 */
export type CommandDescriptor =
  | {
      kind: 'create';
      parent: Uint8Array;
      name: string;
      nodeKind: NodeKind;
      content: ArrayBuffer | null;
    }
  | { kind: 'delete'; node: Uint8Array }
  | { kind: 'rename'; node: Uint8Array; newName: string }
  | { kind: 'relink'; node: Uint8Array; newParent: Uint8Array }
  | { kind: 'updateContent'; node: Uint8Array; content: ArrayBuffer }
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
  | { kind: 'siweLogin'; message: string; signature: Uint8Array }
  | { kind: 'logout' };

/** One event the engine emitted, as data (mirrors the facade `Event`). */
export type EventDescriptor =
  | { kind: 'snapshotUpdated' }
  | { kind: 'stalenessChanged'; staleness: Staleness }
  | { kind: 'withheldUpdateEscalation'; ipnsName: Uint8Array }
  | { kind: 'deadLetter'; opId: bigint }
  | { kind: 'attributableAbuse'; description: string }
  | { kind: 'renewalFailed'; routingKey: string; detail: string }
  | {
      kind: 'opProgress';
      opId: bigint | null;
      node: Uint8Array;
      phase: OpProgressPhase;
      error: string | null;
    };

/** A UI → worker request. `id` correlates the eventual response. */
export type WorkerRequest =
  | { type: 'start'; id: number; secret: ArrayBuffer }
  | { type: 'command'; id: number; command: CommandDescriptor }
  | { type: 'snapshot'; id: number; folder: Uint8Array }
  | { type: 'download'; id: number; node: Uint8Array };

/** A worker → UI message. */
export type WorkerMessage =
  /**
   * The worker has instantiated the engine and is ready for requests.
   * `storagePersisted` reports whether the origin holds persistent-storage
   * permission, so the host can warn that queued work may be evicted; absent
   * means the worker did not report a grant, which the host reads as denied.
   */
  | { type: 'ready'; storagePersisted?: boolean }
  /**
   * The correlated result of a request. A read request's ok response carries
   * its value: a `SnapshotDescriptor` for `snapshot`, the plaintext
   * `ArrayBuffer` (transferred, not copied) for `download`.
   */
  | { type: 'response'; id: number; ok: true; result?: SnapshotDescriptor | ArrayBuffer }
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
