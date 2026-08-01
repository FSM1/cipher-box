/**
 * The minimal structural type of the wasm-bindgen engine module, as the worker
 * uses it.
 *
 * The wasm-bindgen `.d.ts` is the real boundary contract, but it is a build
 * artifact (generated into the worker's `pkg` dir), not importable from `src`.
 * This interface names only the constructor/handle/builder surface the worker
 * drives, so the worker plumbing typechecks without the artifact; the concrete
 * generated module satisfies it structurally at wiring time. It is not a mirror
 * of engine *view* structures (those never cross to this layer) — only the
 * stable command/handle surface frozen in `crates/wasm`.
 */

/** Opaque wasm-bindgen `NodeId` handle. */
export type WasmNodeId = object;

/** Opaque wasm-bindgen `Command` handle. */
export type WasmCommand = object;

/** wasm-bindgen `Event` — key-free view state; a getter is `undefined` off-variant. */
export interface WasmEvent {
  readonly kind: string;
  readonly staleness?: number;
  readonly ipnsName?: Uint8Array;
  readonly opId?: bigint;
  readonly description?: string;
  readonly node?: Uint8Array;
  readonly phase?: number;
  readonly blocksConfirmed?: number;
  readonly blocksTotal?: number;
  readonly error?: string;
  readonly routingKey?: string;
  readonly detail?: string;
  readonly deadLetterReason?: number;
}

/** wasm-bindgen `Breadcrumb` — one ancestor step in a snapshot view. */
export interface WasmBreadcrumb {
  readonly id: Uint8Array;
  readonly name: string;
}

/** wasm-bindgen `SnapshotChild` — one direct child in a snapshot view. */
export interface WasmSnapshotChild {
  readonly id: Uint8Array;
  readonly name: string;
  readonly kind: number;
  readonly size?: bigint;
  readonly mtime?: bigint;
  readonly pending: number;
  readonly deadLetter: boolean;
  readonly contentVersion?: bigint;
}

/** wasm-bindgen `DeadLetter` — one retained dead-lettered op and its reason. */
export interface WasmDeadLetter {
  readonly opId: bigint;
  readonly reason: number;
}

/** wasm-bindgen `BlockedOp` — the drain's over-budget hold. */
export interface WasmBlockedOp {
  readonly opId: bigint;
  readonly node: Uint8Array;
  readonly neededBytes: bigint;
}

/** wasm-bindgen `SnapshotView` — a key-free folder snapshot for a UI paint. */
export interface WasmSnapshotView {
  readonly root: Uint8Array;
  readonly folder: Uint8Array;
  readonly children: WasmSnapshotChild[];
  readonly ancestors: WasmBreadcrumb[];
  readonly deadLetters: readonly WasmDeadLetter[];
  readonly blocked?: WasmBlockedOp;
  readonly retainedRecords: number;
  readonly staleness: number;
}

/** wasm-bindgen `EngineHandle` — the one engine instance. */
export interface WasmEngineHandle {
  start(secret: Uint8Array): Promise<unknown>;
  command(command: WasmCommand): Promise<unknown>;
  /** Either `(parent, name)` or `(node)` — never both, never neither. */
  beginWrite(
    parent: WasmNodeId | undefined,
    name: string | undefined,
    node: WasmNodeId | undefined,
    size: number
  ): Promise<bigint>;
  pushChunk(handle: bigint, chunk: Uint8Array): Promise<unknown>;
  commitWrite(handle: bigint): Promise<bigint>;
  abortWrite(handle: bigint): Promise<unknown>;
  snapshot(folder?: WasmNodeId): Promise<WasmSnapshotView>;
  siweChallenge(): Promise<string>;
  download(node: WasmNodeId): Promise<Uint8Array>;
  nextEvent(): Promise<WasmEvent | undefined>;
}

/** The wasm-bindgen module namespace the worker binds against. */
export interface EngineWasm {
  EngineHandle: new (
    seams: unknown,
    profile?: string,
    apiBaseUrl?: string,
    acceleratorBaseUrl?: string,
    acceleratorBearer?: string,
    publicGateways?: string[],
    storageHeadroomBytes?: number
  ) => WasmEngineHandle;
  NodeId: { fromBytes(bytes: Uint8Array): WasmNodeId };
  Command: {
    create(parent: WasmNodeId, name: string, kind: number): WasmCommand;
    delete(node: WasmNodeId): WasmCommand;
    rename(node: WasmNodeId, newName: string): WasmCommand;
    relink(node: WasmNodeId, newParent: WasmNodeId): WasmCommand;
    cancelUpload(opId: bigint): WasmCommand;
    setFocus(node?: WasmNodeId): WasmCommand;
    manualRefresh(): WasmCommand;
    importContact(contactCode: Uint8Array): WasmCommand;
    grant(
      node: WasmNodeId,
      recipientIdentityPublicKey: Uint8Array,
      permission: number
    ): WasmCommand;
    revoke(node: WasmNodeId, recipientIdentityPublicKey: Uint8Array): WasmCommand;
    downgrade(node: WasmNodeId, recipientIdentityPublicKey: Uint8Array): WasmCommand;
    createInviteLink(node: WasmNodeId, permission: number): WasmCommand;
    acceptShare(sealedSharePointer: Uint8Array): WasmCommand;
    rotateNow(node: WasmNodeId): WasmCommand;
    siweLogin(message: string, signature: Uint8Array): WasmCommand;
    logout(): WasmCommand;
  };
  NodeKind: { readonly File: number; readonly Folder: number };
  PendingClass: {
    readonly None: number;
    readonly Metadata: number;
    readonly Content: number;
  };
  Permission: { readonly Read: number; readonly Write: number };
  OpPhase: {
    readonly DownloadStarted: number;
    readonly DownloadCompleted: number;
    readonly DownloadFailed: number;
    readonly UploadStarted: number;
    readonly UploadProgress: number;
    readonly UploadCompleted: number;
    readonly UploadFailed: number;
    readonly UploadCancelled: number;
  };
  Staleness: {
    readonly Fresh: number;
    readonly Reconciling: number;
    readonly Stale: number;
    readonly Offline: number;
  };
  DeadLetterReason: {
    readonly TargetGone: number;
    readonly DestinationGone: number;
    readonly DestinationInsideTarget: number;
    readonly SuffixExhausted: number;
    readonly Undecodable: number;
    readonly PayloadRefused: number;
    readonly AttemptsExhausted: number;
    readonly ContentUnrecoverable: number;
  };
}
