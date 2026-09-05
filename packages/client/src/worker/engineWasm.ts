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

import type { SiweIntent } from './protocol.js';

/** Opaque wasm-bindgen `NodeId` handle. */
export type WasmNodeId = object;

/** Opaque wasm-bindgen `Command` handle. */
export type WasmCommand = object;

/** Opaque wasm-bindgen `ByoIpfsConfig` handle. */
export type WasmByoIpfsConfig = object;

/** Opaque wasm-bindgen `VaultSettings` handle. */
export type WasmVaultSettings = object;

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
  readonly retryable?: boolean;
  readonly deadLetterReason?: number;
  readonly scopeRoot?: Uint8Array;
}

/**
 * wasm-bindgen `CommandOutcome` — what one command produced. Unlike the plain
 * views above it is an exported class holding a pointer into WASM memory, so
 * the caller owns it: read the getters, then `free()`.
 */
export interface WasmCommandOutcome {
  readonly kind: string;
  readonly opId?: bigint;
  readonly identityPublicKey?: Uint8Array;
  readonly encPublicKey?: Uint8Array;
  readonly fragment?: string;
  readonly scopeId?: Uint8Array;
  readonly sequence?: bigint;
  readonly permission?: number;
  readonly newlyAdded?: boolean;
  free(): void;
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
  readonly contentCid?: Uint8Array;
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

/**
 * wasm-bindgen `SettingsHold` / `BinIndexHold` — a held queue head and the
 * stable check name of what refused it. The two carry different check
 * vocabularies, which `protocol.ts` maps apart.
 */
export interface WasmQueueHold {
  readonly opId: bigint;
  readonly node: Uint8Array;
  readonly check: string;
}

/**
 * wasm-bindgen `OpenedStream` — a read stream and the size of its pinned
 * version. Like `WasmCommandOutcome` it is an exported class holding a pointer
 * into WASM memory, so the caller owns it: read the getters, then `free()`.
 */
export interface WasmOpenedStream {
  readonly handle: bigint;
  readonly size: number;
  free(): void;
}

/** wasm-bindgen `SnapshotView` — a key-free folder snapshot for a UI paint. */
export interface WasmSnapshotView {
  readonly root: Uint8Array;
  readonly folder: Uint8Array;
  readonly folderName: string;
  readonly children: WasmSnapshotChild[];
  readonly ancestors: WasmBreadcrumb[];
  readonly deadLetters: readonly WasmDeadLetter[];
  readonly blocked?: WasmBlockedOp;
  readonly settingsHold?: WasmQueueHold;
  readonly binIndexHold?: WasmQueueHold;
  readonly retainedRecords: number;
  readonly staleness: number;
}

/** wasm-bindgen `SharingContact` — one contact the vault's book holds. */
export interface WasmSharingContact {
  readonly identityPublicKey: Uint8Array;
}

/** wasm-bindgen `SharingGrant` — one grant a scope's ledger commits. */
export interface WasmSharingGrant {
  readonly recipientIdentityPublicKey: Uint8Array;
  readonly permission: number;
}

/** wasm-bindgen `SharingInviteLinks` — a scope's invite-link standing. */
export interface WasmSharingInviteLinks {
  readonly live: boolean;
  readonly expired: boolean;
  readonly expiresAt?: bigint;
  readonly spent: number;
}

/** wasm-bindgen `ScopeSharing` — what one scope's own record says. */
export interface WasmScopeSharing {
  readonly grants: readonly WasmSharingGrant[];
  readonly grantRefusal?: string;
  readonly inviteLinkRefusal?: string;
  readonly inviteLinks?: WasmSharingInviteLinks;
}

/** wasm-bindgen `SharingView` — a key-free read of one scope's sharing state. */
export interface WasmSharingView {
  readonly scope: Uint8Array;
  readonly contacts: readonly WasmSharingContact[];
  readonly ownContactCode: Uint8Array;
  readonly state?: WasmScopeSharing;
}

/** wasm-bindgen `ReceivedShareRow` — one share this vault accepted. */
export interface WasmReceivedShareRow {
  readonly scope: Uint8Array;
  readonly sharerIdentityPublicKey: Uint8Array;
  readonly displayName: string;
  readonly permission: number;
  readonly resolution?: string;
}

/** wasm-bindgen `BinRow` — one soft-deleted node, key-free by construction. */
export interface WasmBinRow {
  readonly node: Uint8Array;
  readonly kind: number;
  readonly originParent: Uint8Array;
  readonly originName: string;
  readonly originFolderKind: number;
  readonly originFolderName: string;
  readonly deletedAt: bigint;
  readonly scope: Uint8Array;
}

/** wasm-bindgen `BinView` — the `/bin` route's whole read. */
export interface WasmBinView {
  readonly entries: readonly WasmBinRow[];
  readonly origin: number;
}

/**
 * wasm-bindgen `VaultSettingsSummary` — the member's settings minus the provider
 * credential, which has no getter anywhere on the boundary.
 */
export interface WasmVaultSettingsSummary {
  readonly pinMode: number;
  readonly byoEndpoint?: string;
  readonly byoKind?: number;
  readonly byoCredentialStored: boolean;
  readonly keepLatestVersions?: number;
  readonly binRetentionDays: number;
  readonly origin: number;
}

/** wasm-bindgen `QuotaView` — the account's hosted-storage figures. */
export interface WasmQuotaView {
  readonly usedBytes: bigint;
  readonly limitBytes: bigint;
  readonly advisory: boolean;
}

/** wasm-bindgen `ReclaimStall` — one debt a reclaim pass left owed. */
export interface WasmReclaimStall {
  readonly node: Uint8Array;
  readonly target: string;
  readonly reason: number;
}

/** wasm-bindgen `VaultStorageView` — the storage pane's whole read. */
export interface WasmVaultStorageView {
  readonly settings: WasmVaultSettingsSummary;
  readonly quota?: WasmQuotaView;
  readonly pendingReclaimBytes: bigint;
  readonly pendingReclaimIsPartial: boolean;
  readonly reclaimStalls: readonly WasmReclaimStall[];
}

/** wasm-bindgen `AuthMethod` — one login method, in display form. */
export interface WasmAuthMethod {
  readonly id: string;
  readonly kind: number;
  readonly identifierDisplay?: string;
  readonly createdAt: string;
  readonly lastUsedAt?: string;
}

/** wasm-bindgen `RegisteredDevice` — one device identity key on the registry. */
export interface WasmRegisteredDevice {
  readonly id: string;
  readonly publicKey: string;
  readonly label?: string;
  readonly createdAt: string;
  readonly lastSeenAt: string;
}

/** wasm-bindgen `PendingApproval` — one rendezvous awaiting an answer. */
export interface WasmPendingApproval {
  readonly requestId: string;
  readonly requesterDevicePublicKey: string;
  readonly ephemeralPublicKey: string;
  readonly comparisonValue: string;
  readonly createdAt: string;
  readonly expiresAt: string;
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
  command(command: WasmCommand): Promise<WasmCommandOutcome>;
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
  snapshot(folder?: WasmNodeId): Promise<WasmSnapshotView>;
  sharing(scopeRoot?: WasmNodeId): Promise<WasmSharingView>;
  receivedShares(): Promise<readonly WasmReceivedShareRow[]>;
  bin(): Promise<WasmBinView>;
  vaultStorage(): Promise<WasmVaultStorageView>;
  authMethods(): Promise<readonly WasmAuthMethod[]>;
  devices(): Promise<readonly WasmRegisteredDevice[]>;
  deviceRegistrationChallenge(devicePublicKey: string): Promise<Uint8Array>;
  pendingApprovals(): Promise<readonly WasmPendingApproval[]>;
  siweChallenge(intent: SiweIntent): Promise<string>;
  download(node: WasmNodeId): Promise<Uint8Array>;
  openContentStream(node: WasmNodeId): Promise<WasmOpenedStream>;
  /** `offset`/`length` cross as plain JS numbers (the seam's `f64` convention). */
  readStream(handle: bigint, offset: number, length: number): Promise<Uint8Array>;
  closeStream(handle: bigint): Promise<unknown>;
  nextEvent(): Promise<WasmEvent | undefined>;
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
  Command: {
    create(parent: WasmNodeId, name: string, kind: number): WasmCommand;
    delete(node: WasmNodeId): WasmCommand;
    restore(node: WasmNodeId, into?: WasmNodeId): WasmCommand;
    purge(node: WasmNodeId): WasmCommand;
    rename(node: WasmNodeId, newName: string): WasmCommand;
    relink(node: WasmNodeId, newParent: WasmNodeId): WasmCommand;
    cancelUpload(opId: bigint): WasmCommand;
    discardDeadLetter(opId: bigint): WasmCommand;
    recoverDeadLetter(opId: bigint): WasmCommand;
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
    createInviteLink(node: WasmNodeId, permission: number, expiresAt?: bigint): WasmCommand;
    revokeInviteLink(node: WasmNodeId): WasmCommand;
    pruneInviteLinks(node: WasmNodeId): WasmCommand;
    claimInviteLink(fragment: string): WasmCommand;
    convertInviteClaims(node: WasmNodeId): WasmCommand;
    rotateNow(node: WasmNodeId): WasmCommand;
    saveVaultSettings(settings: WasmVaultSettings): WasmCommand;
    siweLink(message: string, signature: Uint8Array): WasmCommand;
    unlinkAuthMethod(methodId: string): WasmCommand;
    registerDevice(
      publicKey: string,
      signature: string,
      identityToken: string,
      label?: string
    ): WasmCommand;
    revokeDevice(deviceId: string): WasmCommand;
    respondToApproval(
      requestId: string,
      decision: number,
      devicePublicKey: string,
      ephemeralPublicKey: string,
      signature: string,
      sealedFactor?: string
    ): WasmCommand;
    logout(): WasmCommand;
    forgetDevice(): WasmCommand;
  };
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
  ByoIpfsConfig: new (
    endpoint: string,
    kind: number,
    accessToken?: Uint8Array
  ) => WasmByoIpfsConfig;
  VaultSettings: new (
    pinMode: number,
    byo?: WasmByoIpfsConfig,
    keepLatestVersions?: number,
    binRetentionDays?: number
  ) => WasmVaultSettings;
  NodeKind: { readonly File: number; readonly Folder: number };
  PendingClass: {
    readonly None: number;
    readonly Metadata: number;
    readonly Content: number;
  };
  Permission: { readonly Read: number; readonly Write: number };
  PinMode: { readonly Hosted: number; readonly External: number; readonly Dual: number };
  ByoKind: { readonly Kubo: number; readonly Psa: number; readonly Pinata: number };
  SettingsOrigin: {
    readonly Resolved: number;
    readonly Stale: number;
    readonly Defaults: number;
  };
  BinOriginKind: {
    readonly Root: number;
    readonly Folder: number;
    readonly Gone: number;
  };
  ReclaimStallReason: {
    readonly NodeUnreadable: number;
    readonly TargetStillLive: number;
    readonly TargetUnexpandable: number;
  };
  AuthMethodKind: {
    readonly Identity: number;
    readonly Wallet: number;
    readonly Test: number;
    readonly Unknown: number;
  };
  ApprovalDecision: { readonly Approve: number; readonly Deny: number };
  OpPhase: {
    readonly DownloadStarted: number;
    readonly DownloadCompleted: number;
    readonly DownloadFailed: number;
    readonly UploadStarted: number;
    readonly UploadProgress: number;
    readonly UploadCompleted: number;
    readonly UploadFailed: number;
    readonly UploadCancelled: number;
    readonly ExternalPinFailed: number;
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
    readonly BaseSuperseded: number;
    readonly HeadTooLarge: number;
    readonly PreservationRefused: number;
    readonly AlreadyPublished: number;
    readonly TargetStillLinked: number;
    readonly ScopeRootNotResealable: number;
    readonly BinIndexFull: number;
    readonly CrossingUnauthorable: number;
    readonly BinIndexStrandedMint: number;
    readonly TargetLinkedAcrossScopes: number;
  };
}
