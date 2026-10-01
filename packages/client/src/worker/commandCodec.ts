/**
 * Translates between the plain-data wire protocol and the wasm-bindgen facade
 * types, inside the engine worker realm: the checkers for the request fields a
 * read or a write handle carries, the readers that turn a view's key-free
 * getters into a descriptor, and the fail-closed read of an event. No
 * interpretation, no crypto — the engine below the facade owns all of that.
 */

import { BIN_INDEX_HOLD_CHECKS, MAX_FRAGMENT_CHARS, SETTINGS_HOLD_CHECKS } from './protocol.js';
import type {
  AuthMethodDescriptor,
  AuthMethodKind,
  BinDescriptor,
  BinOriginDescriptor,
  ByoKind,
  DeadLetterReason,
  EventDescriptor,
  InvitePreviewDescriptor,
  InvitePreviewState,
  NodeKind,
  OpProgressPhase,
  PendingApprovalDescriptor,
  PendingClass,
  Permission,
  PinMode,
  ReceivedShareDescriptor,
  ReceivedShareResolution,
  ReclaimStallReason,
  RegisteredDeviceDescriptor,
  VersionEntryDescriptor,
  SettingsOrigin,
  SharingDescriptor,
  SharingInviteLinkDescriptor,
  SharingGrantDescriptor,
  QueueHoldDescriptor,
  SnapshotDescriptor,
  Staleness,
  VaultStorageDescriptor,
} from './protocol.js';
import type {
  EngineWasm,
  WasmAuthMethod,
  WasmBinRow,
  WasmBinView,
  WasmInvitePreview,
  WasmNodeId,
  WasmPendingApproval,
  WasmQueueHold,
  WasmReceivedShareRow,
  WasmRegisteredDevice,
  WasmVersionEntry,
  WasmSharingInviteLink,
  WasmSharingGrant,
  WasmSharingView,
  WasmSnapshotView,
  WasmVaultStorageView,
} from './engineWasm.js';

/**
 * A request crosses a realm boundary as plain data, so its fields arrive
 * untrusted however they are typed here: a version-skewed peer can carry a
 * wrong-typed one, and wasm-bindgen would coerce it — a 16-character string set
 * into a `Vec<u8>` as sixteen zero bytes — rather than reject it. Hence the
 * checkers below take `unknown`, and every field the worker reads off a read or
 * a write-handle request passes through one. A command is checked by the
 * engine's own decode instead.
 */
function invalidField(field: string, value: unknown): Error {
  return new Error(`invalid request field ${field}: ${value === null ? 'null' : typeof value}`);
}

/** An untrusted wire object; a non-object carries no fields at all. */
export function record(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null) throw invalidField(field, value);
  return value as Record<string, unknown>;
}

export function bytes(value: unknown, field: string): Uint8Array {
  if (!(value instanceof Uint8Array)) throw invalidField(field, value);
  return value;
}

/**
 * A transferred payload. `new Uint8Array(value)` coerces anything else into a
 * plausible view — a string of digits becomes that many zero bytes — so the
 * buffer is checked before a view is taken over it.
 */
export function buffer(value: unknown, field: string): ArrayBuffer {
  if (!(value instanceof ArrayBuffer)) throw invalidField(field, value);
  return value;
}

export function text(value: unknown, field: string): string {
  if (typeof value !== 'string') throw invalidField(field, value);
  return value;
}

/**
 * A byte count or offset. The number ABI coerces rather than rejects — a string
 * or a `NaN` arrives as a valid-looking integer — so the range the engine can
 * actually act on is checked here.
 */
export function count(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw invalidField(field, value);
  }
  return value;
}

/**
 * A value the engine minted and a peer is handing back — a write or stream
 * handle. The bigint ABI throws on a non-bigint where the number one
 * would coerce, so the refusal is spelled here in the same words as its
 * neighbours rather than left to wasm-bindgen.
 */
export function minted(value: unknown, field: string): bigint {
  if (typeof value !== 'bigint') throw invalidField(field, value);
  return value;
}

/**
 * A bearer link's URL fragment, length-guarded before the copy into wasm linear
 * memory. Like every refusal here it names the field and never echoes the
 * value, which is the capability itself.
 */
export function fragment(value: unknown, field: string): string {
  const carried = text(value, field);
  if (carried.length > MAX_FRAGMENT_CHARS) throw invalidField(field, value);
  return carried;
}

export function nodeId(wasm: EngineWasm, value: unknown, field: string): WasmNodeId {
  return wasm.NodeId.fromBytes(bytes(value, field));
}

function staleness(wasm: EngineWasm, level: number): Staleness {
  switch (level) {
    case wasm.ViewStaleness.Fresh:
      return 'fresh';
    case wasm.ViewStaleness.Reconciling:
      return 'reconciling';
    case wasm.ViewStaleness.Stale:
      return 'stale';
    case wasm.ViewStaleness.Offline:
      return 'offline';
    default:
      // Fail closed: an unmapped value means a JS/WASM version mismatch, not a
      // safe-to-ignore state (the event pump turns this throw into a fatal).
      throw new Error(`unknown WASM staleness value: ${level}`);
  }
}

function pendingClass(wasm: EngineWasm, pending: number): PendingClass {
  switch (pending) {
    case wasm.PendingClass.None:
      return 'none';
    case wasm.PendingClass.Metadata:
      return 'metadata';
    case wasm.PendingClass.Content:
      return 'content';
    default:
      // Fail closed: an unmapped value means a JS/WASM version mismatch.
      throw new Error(`unknown WASM pending class value: ${pending}`);
  }
}

function deadLetterReason(wasm: EngineWasm, reason: number): DeadLetterReason {
  switch (reason) {
    case wasm.ViewDeadLetterReason.TargetGone:
      return 'targetGone';
    case wasm.ViewDeadLetterReason.DestinationGone:
      return 'destinationGone';
    case wasm.ViewDeadLetterReason.DestinationInsideTarget:
      return 'destinationInsideTarget';
    case wasm.ViewDeadLetterReason.SuffixExhausted:
      return 'suffixExhausted';
    case wasm.ViewDeadLetterReason.Undecodable:
      return 'undecodable';
    case wasm.ViewDeadLetterReason.PayloadRefused:
      return 'payloadRefused';
    case wasm.ViewDeadLetterReason.AttemptsExhausted:
      return 'attemptsExhausted';
    case wasm.ViewDeadLetterReason.ContentUnrecoverable:
      return 'contentUnrecoverable';
    case wasm.ViewDeadLetterReason.BaseSuperseded:
      return 'baseSuperseded';
    case wasm.ViewDeadLetterReason.HeadTooLarge:
      return 'headTooLarge';
    case wasm.ViewDeadLetterReason.PreservationRefused:
      return 'preservationRefused';
    case wasm.ViewDeadLetterReason.AlreadyPublished:
      return 'alreadyPublished';
    case wasm.ViewDeadLetterReason.TargetStillLinked:
      return 'targetStillLinked';
    case wasm.ViewDeadLetterReason.ScopeRootNotResealable:
      return 'scopeRootNotResealable';
    case wasm.ViewDeadLetterReason.BinIndexFull:
      return 'binIndexFull';
    case wasm.ViewDeadLetterReason.CrossingUnauthorable:
      return 'crossingUnauthorable';
    case wasm.ViewDeadLetterReason.BinIndexStrandedMint:
      return 'binIndexStrandedMint';
    case wasm.ViewDeadLetterReason.TargetLinkedAcrossScopes:
      return 'targetLinkedAcrossScopes';
    case wasm.ViewDeadLetterReason.GraftedScopeVaultSurface:
      return 'graftedScopeVaultSurface';
    default:
      // Fail closed: an unmapped value means a JS/WASM version mismatch, not a
      // dead letter safe to report without its reason.
      throw new Error(`unknown WASM dead letter reason value: ${reason}`);
  }
}

/**
 * Reads the held queue head, refusing a reason or a check name this build does
 * not know. A hold whose cause cannot be named would render as an unexplained
 * stall, which is the state the hold exists to remove.
 */
function queueHold(hold: WasmQueueHold | undefined): QueueHoldDescriptor | null {
  if (hold === undefined) return null;
  const head = { opId: hold.opId, node: hold.node };
  switch (hold.reason) {
    case 'quota':
      if (hold.neededBytes === undefined) {
        throw new Error('WASM quota hold carries no byte count');
      }
      return { ...head, reason: 'quota', neededBytes: hold.neededBytes };
    case 'settings':
      return { ...head, reason: 'settings', check: holdCheck(hold, SETTINGS_HOLD_CHECKS) };
    case 'bin-index':
      return { ...head, reason: 'bin-index', check: holdCheck(hold, BIN_INDEX_HOLD_CHECKS) };
    default:
      throw new Error(`unknown WASM queue hold reason: ${hold.reason}`);
  }
}

function holdCheck<TCheck extends string>(hold: WasmQueueHold, checks: readonly TCheck[]): TCheck {
  const check = checks.find((known) => known === hold.check);
  if (check === undefined) {
    throw new Error(`unknown WASM ${hold.reason} hold check: ${hold.check}`);
  }
  return check;
}

function nodeKindFrom(wasm: EngineWasm, kind: number): NodeKind {
  switch (kind) {
    case wasm.NodeKind.File:
      return 'file';
    case wasm.NodeKind.Folder:
      return 'folder';
    default:
      // Fail closed: an unmapped value means a JS/WASM version mismatch.
      throw new Error(`unknown WASM node kind value: ${kind}`);
  }
}

const EVENT_KINDS: Record<EventDescriptor['kind'], true> = {
  snapshotUpdated: true,
  stalenessChanged: true,
  withheldUpdateEscalation: true,
  deadLetter: true,
  parkedWritesUnreadable: true,
  registryDebtUnjournaled: true,
  granteeNamesCleared: true,
  conversionRecordUnreadable: true,
  refusedClaimDropped: true,
  attributableAbuse: true,
  renewalFailed: true,
  vaultUnprovisioned: true,
  vaultSettingsChanged: true,
  scopeExitCutOwed: true,
  granteeJoined: true,
  opProgress: true,
};

const STALENESS: Record<Staleness, true> = {
  fresh: true,
  reconciling: true,
  stale: true,
  offline: true,
};

const OP_PHASES: Record<OpProgressPhase, true> = {
  downloadStarted: true,
  downloadCompleted: true,
  downloadFailed: true,
  uploadStarted: true,
  uploadProgress: true,
  uploadCompleted: true,
  uploadFailed: true,
  uploadCancelled: true,
  externalPinFailed: true,
};

const DEAD_LETTER_REASONS: Record<DeadLetterReason, true> = {
  targetGone: true,
  destinationGone: true,
  destinationInsideTarget: true,
  suffixExhausted: true,
  undecodable: true,
  payloadRefused: true,
  attemptsExhausted: true,
  contentUnrecoverable: true,
  baseSuperseded: true,
  headTooLarge: true,
  preservationRefused: true,
  alreadyPublished: true,
  targetStillLinked: true,
  scopeRootNotResealable: true,
  binIndexFull: true,
  crossingUnauthorable: true,
  binIndexStrandedMint: true,
  targetLinkedAcrossScopes: true,
  graftedScopeVaultSurface: true,
};

function known(values: Record<string, true>, value: unknown, what: string): void {
  if (typeof value !== 'string' || !Object.hasOwn(values, value)) {
    throw new Error(`unknown WASM ${what}: ${String(value)}`);
  }
}

/**
 * Passes an engine event through once its kind and each enum value in it are
 * ones this build knows. An unknown value means a JS/WASM version mismatch, not
 * a safe-to-ignore event, so the read fails closed (the event pump turns the
 * throw into a fatal).
 */
export function readEvent(event: EventDescriptor): EventDescriptor {
  known(EVENT_KINDS, event.kind, 'event kind');
  if (event.kind === 'stalenessChanged') known(STALENESS, event.staleness, 'staleness');
  if (event.kind === 'deadLetter') known(DEAD_LETTER_REASONS, event.reason, 'dead letter reason');
  if (event.kind === 'opProgress') known(OP_PHASES, event.phase, 'op phase');
  return event;
}

/** Reads a wasm-bindgen `SnapshotView`'s key-free getters into a descriptor. */
export function readSnapshot(wasm: EngineWasm, view: WasmSnapshotView): SnapshotDescriptor {
  return {
    root: view.root,
    folder: view.folder,
    folderName: view.folderName,
    permission: permissionFrom(wasm, view.permission),
    receivedShare: view.receivedShare,
    children: view.children.map((child) => ({
      id: child.id,
      name: child.name,
      kind: nodeKindFrom(wasm, child.kind),
      size: child.size ?? null,
      mtime: child.mtime ?? null,
      pending: pendingClass(wasm, child.pending),
      deadLetter: child.deadLetter,
      contentVersion: child.contentVersion ?? null,
      contentCid: child.contentCid ?? null,
      pendingInviteClaims: child.pendingInviteClaims,
      ipnsName: child.ipnsName ?? null,
    })),
    ancestors: view.ancestors.map((ancestor) => ({ id: ancestor.id, name: ancestor.name })),
    deadLetters: view.deadLetters.map((dead) => ({
      opId: dead.opId,
      reason: deadLetterReason(wasm, dead.reason),
    })),
    queueHold: queueHold(view.queueHold),
    retainedRecords: view.retainedRecords,
    staleness: staleness(wasm, view.staleness),
  };
}

function pinModeFrom(wasm: EngineWasm, mode: number): PinMode {
  switch (mode) {
    case wasm.ViewPinMode.Hosted:
      return 'hosted';
    case wasm.ViewPinMode.External:
      return 'external';
    case wasm.ViewPinMode.Dual:
      return 'dual';
    default:
      // Fail closed: an unmapped value means a JS/WASM version mismatch, and a
      // guessed mode would misreport where this vault's bytes land.
      throw new Error(`unknown WASM pin mode value: ${mode}`);
  }
}

function byoKindFrom(wasm: EngineWasm, kind: number | undefined): ByoKind | null {
  switch (kind) {
    case undefined:
      return null;
    case wasm.ViewByoKind.Kubo:
      return 'kubo';
    case wasm.ViewByoKind.Psa:
      return 'psa';
    case wasm.ViewByoKind.Pinata:
      return 'pinata';
    default:
      // Fail closed: an unmapped value means a JS/WASM version mismatch.
      throw new Error(`unknown WASM provider kind value: ${kind}`);
  }
}

function settingsOriginFrom(wasm: EngineWasm, origin: number): SettingsOrigin {
  switch (origin) {
    case wasm.SettingsOrigin.Resolved:
      return 'resolved';
    case wasm.SettingsOrigin.Stale:
      return 'stale';
    case wasm.SettingsOrigin.Defaults:
      return 'defaults';
    default:
      // Fail closed: an unmapped value means a JS/WASM version mismatch, and a
      // guessed origin would present the documented defaults as the member's
      // own choice.
      throw new Error(`unknown WASM settings origin value: ${origin}`);
  }
}

function stallReasonFrom(wasm: EngineWasm, reason: number): ReclaimStallReason {
  switch (reason) {
    case wasm.ReclaimStallReason.NodeUnreadable:
      return 'nodeUnreadable';
    case wasm.ReclaimStallReason.TargetStillLive:
      return 'targetStillLive';
    case wasm.ReclaimStallReason.TargetUnexpandable:
      return 'targetUnexpandable';
    default:
      // Fail closed: an unmapped value means a JS/WASM version mismatch, and a
      // stall reported without its reason is the silent failure the ledger
      // exists to surface.
      throw new Error(`unknown WASM reclaim stall reason value: ${reason}`);
  }
}

function authMethodKindFrom(wasm: EngineWasm, kind: number): AuthMethodKind {
  switch (kind) {
    case wasm.AuthMethodKind.Identity:
      return 'identity';
    case wasm.AuthMethodKind.Wallet:
      return 'wallet';
    case wasm.AuthMethodKind.Test:
      return 'test';
    case wasm.AuthMethodKind.Unknown:
      return 'unknown';
    default:
      // Fail closed: an unmapped value means a JS/WASM version mismatch. The
      // engine already spells a kind this build does not know as `Unknown`.
      throw new Error(`unknown WASM auth method kind value: ${kind}`);
  }
}

function binOriginFrom(wasm: EngineWasm, row: WasmBinRow): BinOriginDescriptor {
  switch (row.originFolderKind) {
    case wasm.BinOriginKind.Root:
      return { kind: 'root' };
    case wasm.BinOriginKind.Folder:
      return { kind: 'folder', name: row.originFolderName };
    case wasm.BinOriginKind.Gone:
      return { kind: 'gone' };
    default:
      // Fail closed: an unmapped value means a JS/WASM version mismatch, and
      // guessing would name a folder the engine did not.
      throw new Error(`unknown WASM bin origin kind value: ${row.originFolderKind}`);
  }
}

/** Reads a wasm-bindgen `BinView`'s key-free getters into a descriptor. */
export function readBin(wasm: EngineWasm, view: WasmBinView): BinDescriptor {
  return {
    entries: view.entries.map((row) => ({
      node: row.node,
      kind: nodeKindFrom(wasm, row.kind),
      originParent: row.originParent,
      originName: row.originName,
      originFolder: binOriginFrom(wasm, row),
      deletedAt: row.deletedAt,
      scope: row.scope,
    })),
    origin: settingsOriginFrom(wasm, view.origin),
  };
}

/**
 * Reads a wasm-bindgen `VaultStorageView`'s getters into a descriptor.
 *
 * The `u64` figures narrow to JS numbers here: they are display quantities the
 * chrome does arithmetic on, and no storage figure reaches the safe-integer
 * ceiling.
 */
export function readVaultStorage(
  wasm: EngineWasm,
  view: WasmVaultStorageView
): VaultStorageDescriptor {
  const settings = view.settings;
  const quota = view.quota;
  return {
    settings: {
      pinMode: pinModeFrom(wasm, settings.pinMode),
      byoEndpoint: settings.byoEndpoint ?? null,
      byoKind: byoKindFrom(wasm, settings.byoKind),
      byoCredentialStored: settings.byoCredentialStored,
      keepLatestVersions: settings.keepLatestVersions ?? null,
      binRetentionDays: settings.binRetentionDays,
      origin: settingsOriginFrom(wasm, settings.origin),
    },
    quota:
      quota === undefined
        ? null
        : {
            usedBytes: Number(quota.usedBytes),
            limitBytes: Number(quota.limitBytes),
            advisory: quota.advisory,
          },
    pendingReclaimBytes: Number(view.pendingReclaimBytes),
    pendingReclaimIsPartial: view.pendingReclaimIsPartial,
    reclaimStalls: view.reclaimStalls.map((stall) => ({
      node: stall.node,
      target: stall.target,
      reason: stallReasonFrom(wasm, stall.reason),
    })),
  };
}

/** Reads the wasm-bindgen `AuthMethod` rows into descriptors. */
export function readAuthMethods(
  wasm: EngineWasm,
  rows: readonly WasmAuthMethod[]
): AuthMethodDescriptor[] {
  return rows.map((row) => ({
    id: row.id,
    kind: authMethodKindFrom(wasm, row.kind),
    identifierDisplay: row.identifierDisplay ?? null,
    createdAt: row.createdAt,
    lastUsedAt: row.lastUsedAt ?? null,
  }));
}

/** Reads the wasm-bindgen `RegisteredDevice` rows into descriptors. */
export function readDevices(rows: readonly WasmRegisteredDevice[]): RegisteredDeviceDescriptor[] {
  return rows.map((row) => ({
    id: row.id,
    publicKey: row.publicKey,
    label: row.label ?? null,
    createdAt: row.createdAt,
    lastSeenAt: row.lastSeenAt,
  }));
}

/**
 * Reads the wasm-bindgen `VersionEntry` rows into descriptors.
 *
 * Each row is an owned pointer into WASM memory, so every row is released here,
 * including the rows a mid-list throw never reaches.
 */
export function readFileVersions(rows: readonly WasmVersionEntry[]): VersionEntryDescriptor[] {
  try {
    return rows.map((row) => ({
      contentCid: row.contentCid,
      size: row.size,
      modifiedAt: row.modifiedAt,
    }));
  } finally {
    for (const row of rows) {
      row.free();
    }
  }
}

/** Reads the wasm-bindgen `PendingApproval` rows into descriptors. */
export function readPendingApprovals(
  rows: readonly WasmPendingApproval[]
): PendingApprovalDescriptor[] {
  return rows.map((row) => ({
    requestId: row.requestId,
    requesterDevicePublicKey: row.requesterDevicePublicKey,
    ephemeralPublicKey: row.ephemeralPublicKey,
    comparisonValue: row.comparisonValue,
    createdAt: row.createdAt,
    expiresAt: row.expiresAt,
  }));
}

export function permissionFrom(wasm: EngineWasm, permission: number): Permission {
  switch (permission) {
    case wasm.ViewPermission.Read:
      return 'read';
    case wasm.ViewPermission.Write:
      return 'write';
    default:
      // Fail closed: an unmapped value means a JS/WASM version mismatch, and a
      // guessed permission would misreport who can write to a scope.
      throw new Error(`unknown WASM permission value: ${permission}`);
  }
}

/**
 * The verdicts `ResolutionClass::name` produces, and nothing else: an
 * unmapped string is a JS/WASM version mismatch, and guessing one would paint a
 * revoked share as still granted.
 */
function resolution(name: string | undefined): ReceivedShareResolution | null {
  switch (name) {
    case undefined:
      return null;
    case 'granted':
    case 'revocation-signal':
    case 'expired':
    case 'unresolvable':
    case 'epoch-lag':
      return name;
    default:
      throw new Error(`unknown WASM resolution class: ${name}`);
  }
}

/**
 * Fails closed on a source this build does not know: it is a JS/WASM version
 * mismatch, and a guessed source would misreport who chose the name.
 */
function granteeName(grant: WasmSharingGrant): SharingGrantDescriptor['granteeName'] {
  const named = grant.granteeName;
  if (named === undefined) return null;
  const { name, source } = named;
  if (source === 'owner' || source === 'claimant') return { name, source };
  throw new Error(`unknown WASM grantee name source: ${source}`);
}

/** Reads a wasm-bindgen `ReceivedShareRow`'s getters into a descriptor. */
export function readReceivedShare(
  wasm: EngineWasm,
  row: WasmReceivedShareRow
): ReceivedShareDescriptor {
  return {
    scope: row.scope,
    sharerIdentityPublicKey: row.sharerIdentityPublicKey,
    displayName: row.displayName,
    permission: permissionFrom(wasm, row.permission),
    resolution: resolution(row.resolution),
    viaLink: row.viaLink,
  };
}

/**
 * The states `LinkPreviewState::name` produces, and nothing else: an unmapped
 * string is a JS/WASM version mismatch, and guessing one could offer "join" on
 * a revoked link.
 */
function previewState(name: string): InvitePreviewState {
  switch (name) {
    case 'live':
    case 'expired':
    case 'revoked':
    case 'unresolvable':
      return name;
    default:
      throw new Error(`unknown WASM invite preview state: ${name}`);
  }
}

/**
 * Reads a wasm-bindgen `InvitePreview`'s getters into a descriptor. The names
 * cross together or not at all: one without the other is a version mismatch.
 */
export function readInvitePreview(
  wasm: EngineWasm,
  preview: WasmInvitePreview
): InvitePreviewDescriptor {
  const { ownerName, folderName, permission } = preview;
  if ((ownerName === undefined) !== (folderName === undefined)) {
    throw new Error('WASM invite preview carries one name without the other');
  }
  return {
    scope: preview.scope,
    names: ownerName === undefined || folderName === undefined ? null : { ownerName, folderName },
    permission: permission === undefined ? null : permissionFrom(wasm, permission),
    state: previewState(preview.state),
    joined: preview.joined,
    listing: preview.listing.map((entry) => ({
      name: entry.name,
      kind: nodeKindFrom(wasm, entry.kind),
    })),
  };
}

function readInviteLink(
  wasm: EngineWasm,
  link: WasmSharingInviteLink
): SharingInviteLinkDescriptor {
  return {
    tag: link.tag,
    permission: permissionFrom(wasm, link.permission),
    expiresAt: link.expiresAt,
    expired: link.expired,
    admissionCap: Number(link.admissionCap),
    pendingClaims: link.pendingClaims,
    contactBudgetFull: link.contactBudgetFull,
    refusedClaims: link.refusedClaims,
  };
}

/**
 * Reads a wasm-bindgen `SharingView`'s key-free getters into a descriptor.
 *
 * Every getter is read once into a local: each read mints a fresh JS wrapper
 * over a fresh boxed Rust struct, which nothing here frees.
 */
export function readSharing(wasm: EngineWasm, view: WasmSharingView): SharingDescriptor {
  const state = view.state;
  const readEpoch = state?.readEpoch;
  const writeEpoch = state?.writeEpoch;
  return {
    scope: view.scope,
    contacts: view.contacts.map((contact) => ({
      identityPublicKey: contact.identityPublicKey,
      cachedName: contact.cachedName ?? null,
    })),
    ownContactCode: view.ownContactCode,
    state:
      state === undefined
        ? null
        : {
            grants: state.grants.map((grant) => ({
              recipientIdentityPublicKey: grant.recipientIdentityPublicKey,
              permission: permissionFrom(wasm, grant.permission),
              granteeName: granteeName(grant),
              viaLink: grant.viaLink ?? null,
            })),
            grantRefusal: state.grantRefusal ?? null,
            inviteLinkRefusal: state.inviteLinkRefusal ?? null,
            inviteLinks: state.inviteLinks.map((link) => readInviteLink(wasm, link)),
            epochs:
              readEpoch === undefined || writeEpoch === undefined
                ? null
                : { readEpoch, writeEpoch },
          },
  };
}
