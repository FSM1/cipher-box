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
  readonly error?: string;
  readonly routingKey?: string;
  readonly detail?: string;
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

/** wasm-bindgen `SnapshotView` — a key-free folder snapshot for a UI paint. */
export interface WasmSnapshotView {
  readonly root: Uint8Array;
  readonly folder: Uint8Array;
  readonly children: WasmSnapshotChild[];
  readonly ancestors: WasmBreadcrumb[];
  readonly deadLetters: BigUint64Array;
  readonly staleness: number;
}

/** wasm-bindgen `EngineHandle` — the one engine instance. */
export interface WasmEngineHandle {
  start(secret: Uint8Array): Promise<unknown>;
  command(command: WasmCommand): Promise<unknown>;
  snapshot(folder: WasmNodeId): Promise<WasmSnapshotView>;
  download(node: WasmNodeId): Promise<Uint8Array>;
  nextEvent(): Promise<WasmEvent | undefined>;
}

/** The wasm-bindgen module namespace the worker binds against. */
export interface EngineWasm {
  EngineHandle: new (seams: unknown, profile?: string) => WasmEngineHandle;
  NodeId: { fromBytes(bytes: Uint8Array): WasmNodeId };
  Command: {
    create(parent: WasmNodeId, name: string, kind: number, content?: Uint8Array): WasmCommand;
    delete(node: WasmNodeId): WasmCommand;
    rename(node: WasmNodeId, newName: string): WasmCommand;
    relink(node: WasmNodeId, newParent: WasmNodeId): WasmCommand;
    updateContent(node: WasmNodeId, content: Uint8Array): WasmCommand;
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
  };
  Staleness: {
    readonly Fresh: number;
    readonly Reconciling: number;
    readonly Stale: number;
    readonly Offline: number;
  };
}
