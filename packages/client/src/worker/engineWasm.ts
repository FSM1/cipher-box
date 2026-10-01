/**
 * The minimal structural type of the wasm-bindgen engine module, as the worker
 * uses it.
 *
 * The wasm-bindgen `.d.ts` is the real boundary contract; a command, its
 * outcome, an event and a view are typed from it. The rest of this interface
 * names the handle surface the worker drives, which the generated module
 * satisfies structurally at wiring time.
 */

import type {
  AuthMethod,
  BinView,
  Command,
  CommandOutcome,
  Event,
  InvitePreview,
  NodeId,
  PendingApprovalView,
  ReceivedShareRow,
  RegisteredDevice,
  SharingView,
  SnapshotView,
  VaultStorageView,
  VersionEntry,
} from '../../wasm/cipherbox_wasm.js';
import type { SiweIntent } from './protocol.js';

/** wasm-bindgen `NodeId` handle. */
export type WasmNodeId = NodeId;

/**
 * wasm-bindgen `OpenedStream` — a read stream and the size of its pinned
 * version. It is an exported class holding a pointer into WASM memory, so the
 * caller owns it: read the getters, then `free()`.
 */
export interface WasmOpenedStream {
  readonly handle: bigint;
  readonly size: number;
  free(): void;
}

/** wasm-bindgen `DeviceRendezvous` — what a requester offers and must sign. */
export interface WasmDeviceRendezvous {
  readonly ephemeralPublicKey: string;
  readonly requestPayload: Uint8Array;
  readonly comparisonValue: string;
  free(): void;
}

/** wasm-bindgen `DeviceApprovalResponse` — what an approver sends and must sign. */
export interface WasmDeviceApprovalResponse {
  readonly sealedFactor?: string;
  readonly payload: Uint8Array;
  free(): void;
}

/** wasm-bindgen `EngineHandle` — the one engine instance. */
export interface WasmEngineHandle {
  start(secret: Uint8Array): Promise<unknown>;
  command(command: Command): Promise<CommandOutcome>;
  /**
   * Either `(parent, name)` or `(node)` — never both, never neither.
   * `expectedVersion` belongs to `node` alone.
   */
  beginWrite(
    parent: WasmNodeId | undefined,
    name: string | undefined,
    node: WasmNodeId | undefined,
    size: number,
    expectedVersion: Uint8Array | undefined
  ): Promise<bigint>;
  pushChunk(handle: bigint, chunk: Uint8Array): Promise<unknown>;
  commitWrite(handle: bigint): Promise<bigint>;
  abortWrite(handle: bigint): Promise<unknown>;
  snapshot(folder?: WasmNodeId): Promise<SnapshotView>;
  sharing(scopeRoot?: WasmNodeId): Promise<SharingView>;
  receivedShares(): Promise<ReceivedShareRow[]>;
  previewInviteLink(fragment: string): Promise<InvitePreview>;
  bin(): Promise<BinView>;
  vaultStorage(): Promise<VaultStorageView>;
  authMethods(): Promise<AuthMethod[]>;
  devices(): Promise<RegisteredDevice[]>;
  deviceRegistrationChallenge(devicePublicKey: string): Promise<Uint8Array>;
  pendingApprovals(): Promise<PendingApprovalView[]>;
  siweChallenge(intent: SiweIntent): Promise<string>;
  download(node: WasmNodeId): Promise<Uint8Array>;
  fileVersions(node: WasmNodeId): Promise<VersionEntry[]>;
  downloadVersion(node: WasmNodeId, contentCid: Uint8Array): Promise<Uint8Array>;
  openContentStream(node: WasmNodeId): Promise<WasmOpenedStream>;
  /** `offset`/`length` cross as plain JS numbers (the seam's `f64` convention). */
  readStream(handle: bigint, offset: number, length: number): Promise<Uint8Array>;
  closeStream(handle: bigint): Promise<unknown>;
  nextEvent(): Promise<Event | undefined>;
}

/** The wasm-bindgen module namespace the worker binds against. */
export interface EngineWasm {
  EngineHandle: new (
    seams: unknown,
    profile?: string,
    apiBaseUrl?: string,
    acceleratorBaseUrl?: string,
    publicGateways?: string[],
    storageHeadroomBytes?: number
  ) => WasmEngineHandle;
  NodeId: { fromBytes(bytes: Uint8Array): WasmNodeId };
  /**
   * The rendezvous free functions (ADR 0009). They are pure and hold no engine
   * state, so they hang off the module rather than the handle.
   */
  openDeviceRendezvous(devicePublicKey: string, rendezvousScalar: Uint8Array): WasmDeviceRendezvous;
  approveDeviceRendezvous(
    devicePublicKey: string,
    requestId: string,
    requesterDevicePublicKey: string,
    ephemeralPublicKey: string,
    sealScalar: Uint8Array,
    factorKey: Uint8Array
  ): WasmDeviceApprovalResponse;
  denyDeviceRendezvous(
    devicePublicKey: string,
    requestId: string,
    ephemeralPublicKey: string
  ): WasmDeviceApprovalResponse;
  openDeviceFactor(
    sealedFactor: string,
    requestId: string,
    requesterDevicePublicKey: string,
    responderDevicePublicKey: string,
    responseSignature: string,
    rendezvousScalar: Uint8Array
  ): Uint8Array;
  /** Throws on bytes that are not a compressed secp256k1 identity key. */
  identityFingerprint(identityPublicKey: Uint8Array): string;
}
