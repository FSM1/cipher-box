/**
 * Translates between the plain-data wire protocol and the wasm-bindgen facade
 * types, inside the engine worker realm.
 *
 * `buildCommand` rebuilds a real `Command` from a descriptor via the generated
 * builders; `readEvent` reads a `Event`'s key-free getters into a descriptor.
 * No interpretation, no crypto — the engine below the facade owns all of that.
 */

import { MAX_FRAGMENT_CHARS } from './protocol.js';
import type {
  AuthMethodDescriptor,
  AuthMethodKind,
  BinDescriptor,
  BinOriginDescriptor,
  BlockedOpDescriptor,
  ByoKind,
  CommandDescriptor,
  DeadLetterReason,
  EventDescriptor,
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
  SettingsOrigin,
  SharingDescriptor,
  SnapshotDescriptor,
  Staleness,
  VaultStorageDescriptor,
} from './protocol.js';
import type {
  EngineWasm,
  WasmAuthMethod,
  WasmBinRow,
  WasmBinView,
  WasmBlockedOp,
  WasmCommand,
  WasmEvent,
  WasmByoIpfsConfig,
  WasmNodeId,
  WasmPendingApproval,
  WasmReceivedShareRow,
  WasmRegisteredDevice,
  WasmSharingView,
  WasmSnapshotView,
  WasmVaultSettings,
  WasmVaultStorageView,
} from './engineWasm.js';

/**
 * A request crosses a realm boundary as plain data, so its fields arrive
 * untrusted however they are typed here: a version-skewed peer can carry a
 * wrong-typed one, and wasm-bindgen would coerce it — a `12345` newName
 * marshalled as `"12345"`, a 16-character string set into a `Vec<u8>` as
 * sixteen zero bytes — rather than reject it. Hence the checkers below take
 * `unknown`, and every field the worker reads off a request passes through one.
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
 * A value the engine minted and a peer is handing back — an op id, or a write
 * or stream handle. The bigint ABI throws on a non-bigint where the number one
 * would coerce, so the refusal is spelled here in the same words as its
 * neighbours rather than left to wasm-bindgen.
 */
export function minted(value: unknown, field: string): bigint {
  if (typeof value !== 'bigint') throw invalidField(field, value);
  return value;
}

/**
 * An invite link's Unix-millis deadline, bounded to the `u64` the builder takes:
 * an out-of-range value the bigint ABI truncates would arrive as an unrelated
 * near-epoch deadline. Refused before any wasm object is minted, as
 * [`retentionCap`] is.
 */
function deadline(value: unknown, field: string): bigint {
  const at = minted(value, field);
  if (at <= 0n || at > 0xffff_ffff_ffff_ffffn) throw invalidField(field, value);
  return at;
}

/**
 * A bearer link's URL fragment, length-guarded before the copy into wasm linear
 * memory. Like every refusal here it names the field and never echoes the
 * value, which is the capability itself.
 */
function fragment(value: unknown, field: string): string {
  const carried = text(value, field);
  if (carried.length > MAX_FRAGMENT_CHARS) throw invalidField(field, value);
  return carried;
}

export function nodeId(wasm: EngineWasm, value: unknown, field: string): WasmNodeId {
  return wasm.NodeId.fromBytes(bytes(value, field));
}

function nodeKind(wasm: EngineWasm, value: unknown): number {
  if (value === 'file') return wasm.NodeKind.File;
  if (value === 'folder') return wasm.NodeKind.Folder;
  throw invalidField('nodeKind', value);
}

function permission(wasm: EngineWasm, value: unknown): number {
  if (value === 'read') return wasm.Permission.Read;
  if (value === 'write') return wasm.Permission.Write;
  throw invalidField('permission', value);
}

function approvalDecision(wasm: EngineWasm, value: unknown): number {
  if (value === 'approve') return wasm.ApprovalDecision.Approve;
  if (value === 'deny') return wasm.ApprovalDecision.Deny;
  throw invalidField('decision', value);
}

/** An optional wire string: `null` is the absence the builder takes as `undefined`. */
function optionalText(value: unknown, field: string): string | undefined {
  return value === null ? undefined : text(value, field);
}

function pinMode(wasm: EngineWasm, value: unknown): number {
  if (value === 'hosted') return wasm.PinMode.Hosted;
  if (value === 'external') return wasm.PinMode.External;
  if (value === 'dual') return wasm.PinMode.Dual;
  throw invalidField('settings.pinMode', value);
}

function byoKind(wasm: EngineWasm, value: unknown): number {
  if (value === 'kubo') return wasm.ByoKind.Kubo;
  if (value === 'psa') return wasm.ByoKind.Psa;
  if (value === 'pinata') return wasm.ByoKind.Pinata;
  throw invalidField('settings.byo.kind', value);
}

/**
 * A retention cap. Distinct from [`count`]: the builder takes a `u32` and the
 * JS→wasm number ABI *wraps* rather than rejects, so an over-range value would
 * arrive as an unrelated small cap — `2**32 + 1` as "keep only the newest".
 *
 * Zero is refused here rather than left to the `NonZeroU64` the builder holds:
 * the refusal would otherwise land after `byoConfig` minted a wasm object
 * holding the access token, stranding that allocation with no owner to free it.
 */
function retentionCap(value: unknown, field: string): number {
  const cap = count(value, field);
  if (cap === 0 || cap > 0xffff_ffff) throw invalidField(field, value);
  return cap;
}

/**
 * A bin retention in days, bounded to the `u32` the builder takes for the same
 * reason [`retentionCap`] is: the number ABI wraps rather than rejects. The
 * policy bar itself is the engine's, and the builder names the field when it
 * refuses.
 */
function binRetentionDays(value: unknown, field: string): number {
  const days = count(value, field);
  if (days > 0xffff_ffff) throw invalidField(field, value);
  return days;
}

function byoConfig(
  wasm: EngineWasm,
  value: unknown,
  token: Uint8Array | undefined
): WasmByoIpfsConfig {
  const config = record(value, 'settings.byo');
  return new wasm.ByoIpfsConfig(
    text(config.endpoint, 'settings.byo.endpoint'),
    byoKind(wasm, config.kind),
    token
  );
}

/** The bearer a settings descriptor carries, checked but not yet spent. */
function byoToken(value: unknown): Uint8Array | undefined {
  const byo = record(value, 'settings').byo ?? undefined;
  if (byo === undefined) return undefined;
  const raw = record(byo, 'settings.byo').accessToken ?? undefined;
  // A view over the transferred buffer, not a copy: scrubbing it scrubs the
  // only copy that crossed into this realm.
  return raw === undefined ? undefined : new Uint8Array(buffer(raw, 'settings.byo.accessToken'));
}

/**
 * Every scalar is checked before the first wasm object is built: a `new` that a
 * later refusal abandons strands its allocation — and the credential inside it
 * — in linear memory until the finalization registry runs.
 *
 * The bearer is read first and scrubbed last, so every refusal in between spends
 * it too. It arrives transferred, so this realm holds the only copy and the
 * builder copies what it keeps.
 */
function vaultSettings(wasm: EngineWasm, value: unknown): WasmVaultSettings {
  const token = byoToken(value);
  try {
    const settings = record(value, 'settings');
    const mode = pinMode(wasm, settings.pinMode);
    const rawKeep = settings.keepLatestVersions ?? undefined;
    const keep =
      rawKeep === undefined ? undefined : retentionCap(rawKeep, 'settings.keepLatestVersions');
    const rawBin = settings.binRetentionDays ?? undefined;
    const bin =
      rawBin === undefined ? undefined : binRetentionDays(rawBin, 'settings.binRetentionDays');
    const byo = settings.byo ?? undefined;
    return new wasm.VaultSettings(
      mode,
      byo === undefined ? undefined : byoConfig(wasm, byo, token),
      keep,
      bin
    );
  } finally {
    token?.fill(0);
  }
}

/**
 * Exhaustiveness bound: adding a command kind without a builder fails the
 * build, and a sender off the union gets a refusal rather than the `undefined`
 * command the wasm glue merely happens to reject.
 */
function unknownCommand(descriptor: never): Error {
  return new Error(`unknown command kind: ${String((descriptor as CommandDescriptor).kind)}`);
}

export function buildCommand(wasm: EngineWasm, descriptor: CommandDescriptor): WasmCommand {
  // The envelope is a field like any other: read `kind` off a non-object and
  // the refusal is a TypeError, or an unknown-kind error naming `undefined`,
  // rather than the invalid-field answer every other malformed input gets.
  text(record(descriptor, 'command').kind, 'command.kind');
  switch (descriptor.kind) {
    case 'create':
      return wasm.Command.create(
        nodeId(wasm, descriptor.parent, 'parent'),
        text(descriptor.name, 'name'),
        nodeKind(wasm, descriptor.nodeKind)
      );
    case 'delete':
      return wasm.Command.delete(nodeId(wasm, descriptor.node, 'node'));
    case 'restore':
      return wasm.Command.restore(
        nodeId(wasm, descriptor.node, 'node'),
        descriptor.into === null ? undefined : nodeId(wasm, descriptor.into, 'into')
      );
    case 'purge':
      return wasm.Command.purge(nodeId(wasm, descriptor.node, 'node'));
    case 'rename':
      return wasm.Command.rename(
        nodeId(wasm, descriptor.node, 'node'),
        text(descriptor.newName, 'newName')
      );
    case 'relink':
      return wasm.Command.relink(
        nodeId(wasm, descriptor.node, 'node'),
        nodeId(wasm, descriptor.newParent, 'newParent')
      );
    case 'cancelUpload':
      return wasm.Command.cancelUpload(minted(descriptor.opId, 'opId'));
    case 'discardDeadLetter':
      return wasm.Command.discardDeadLetter(minted(descriptor.opId, 'opId'));
    case 'recoverDeadLetter':
      return wasm.Command.recoverDeadLetter(minted(descriptor.opId, 'opId'));
    case 'setFocus':
      return wasm.Command.setFocus(
        descriptor.node === null ? undefined : nodeId(wasm, descriptor.node, 'node')
      );
    case 'manualRefresh':
      return wasm.Command.manualRefresh();
    case 'importContact':
      return wasm.Command.importContact(bytes(descriptor.contactCode, 'contactCode'));
    case 'grant':
      return wasm.Command.grant(
        nodeId(wasm, descriptor.node, 'node'),
        bytes(descriptor.recipientIdentityPublicKey, 'recipientIdentityPublicKey'),
        permission(wasm, descriptor.permission)
      );
    case 'revoke':
      return wasm.Command.revoke(
        nodeId(wasm, descriptor.node, 'node'),
        bytes(descriptor.recipientIdentityPublicKey, 'recipientIdentityPublicKey')
      );
    case 'downgrade':
      return wasm.Command.downgrade(
        nodeId(wasm, descriptor.node, 'node'),
        bytes(descriptor.recipientIdentityPublicKey, 'recipientIdentityPublicKey')
      );
    case 'createInviteLink': {
      // Every scalar first: a refusal after `nodeId` strands the handle it minted.
      const level = permission(wasm, descriptor.permission);
      const at =
        descriptor.expiresAt == null ? undefined : deadline(descriptor.expiresAt, 'expiresAt');
      return wasm.Command.createInviteLink(nodeId(wasm, descriptor.node, 'node'), level, at);
    }
    case 'revokeInviteLink':
      return wasm.Command.revokeInviteLink(nodeId(wasm, descriptor.node, 'node'));
    case 'pruneInviteLinks':
      return wasm.Command.pruneInviteLinks(nodeId(wasm, descriptor.node, 'node'));
    case 'claimInviteLink':
      return wasm.Command.claimInviteLink(fragment(descriptor.fragment, 'fragment'));
    case 'convertInviteClaims':
      return wasm.Command.convertInviteClaims(nodeId(wasm, descriptor.node, 'node'));
    case 'rotateNow':
      return wasm.Command.rotateNow(nodeId(wasm, descriptor.node, 'node'));
    case 'saveVaultSettings':
      return wasm.Command.saveVaultSettings(vaultSettings(wasm, descriptor.settings));
    case 'siweLink':
      return wasm.Command.siweLink(
        text(descriptor.message, 'message'),
        bytes(descriptor.signature, 'signature')
      );
    case 'unlinkAuthMethod':
      return wasm.Command.unlinkAuthMethod(text(descriptor.methodId, 'methodId'));
    case 'registerDevice':
      return wasm.Command.registerDevice(
        text(descriptor.publicKey, 'publicKey'),
        text(descriptor.signature, 'signature'),
        text(descriptor.identityToken, 'identityToken'),
        optionalText(descriptor.label, 'label')
      );
    case 'revokeDevice':
      return wasm.Command.revokeDevice(text(descriptor.deviceId, 'deviceId'));
    case 'respondToApproval':
      return wasm.Command.respondToApproval(
        text(descriptor.requestId, 'requestId'),
        approvalDecision(wasm, descriptor.decision),
        text(descriptor.devicePublicKey, 'devicePublicKey'),
        text(descriptor.ephemeralPublicKey, 'ephemeralPublicKey'),
        text(descriptor.signature, 'signature'),
        optionalText(descriptor.sealedFactor, 'sealedFactor')
      );
    case 'logout':
      return wasm.Command.logout();
    case 'forgetDevice':
      return wasm.Command.forgetDevice();
    default:
      throw unknownCommand(descriptor);
  }
}

function staleness(wasm: EngineWasm, level: number): Staleness {
  switch (level) {
    case wasm.Staleness.Fresh:
      return 'fresh';
    case wasm.Staleness.Reconciling:
      return 'reconciling';
    case wasm.Staleness.Stale:
      return 'stale';
    case wasm.Staleness.Offline:
      return 'offline';
    default:
      // Fail closed: an unmapped value means a JS/WASM version mismatch, not a
      // safe-to-ignore state (the event pump turns this throw into a fatal).
      throw new Error(`unknown WASM staleness value: ${level}`);
  }
}

function opPhase(wasm: EngineWasm, phase: number | undefined): OpProgressPhase {
  switch (phase) {
    case wasm.OpPhase.DownloadStarted:
      return 'downloadStarted';
    case wasm.OpPhase.DownloadCompleted:
      return 'downloadCompleted';
    case wasm.OpPhase.DownloadFailed:
      return 'downloadFailed';
    case wasm.OpPhase.UploadStarted:
      return 'uploadStarted';
    case wasm.OpPhase.UploadProgress:
      return 'uploadProgress';
    case wasm.OpPhase.UploadCompleted:
      return 'uploadCompleted';
    case wasm.OpPhase.UploadFailed:
      return 'uploadFailed';
    case wasm.OpPhase.UploadCancelled:
      return 'uploadCancelled';
    case wasm.OpPhase.ExternalPinFailed:
      return 'externalPinFailed';
    default:
      // Fail closed: an unmapped value means a JS/WASM version mismatch, not a
      // safe-to-ignore state (the event pump turns this throw into a fatal).
      throw new Error(`unknown WASM op phase value: ${phase}`);
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

function deadLetterReason(wasm: EngineWasm, reason: number | undefined): DeadLetterReason {
  switch (reason) {
    case wasm.DeadLetterReason.TargetGone:
      return 'targetGone';
    case wasm.DeadLetterReason.DestinationGone:
      return 'destinationGone';
    case wasm.DeadLetterReason.DestinationInsideTarget:
      return 'destinationInsideTarget';
    case wasm.DeadLetterReason.SuffixExhausted:
      return 'suffixExhausted';
    case wasm.DeadLetterReason.Undecodable:
      return 'undecodable';
    case wasm.DeadLetterReason.PayloadRefused:
      return 'payloadRefused';
    case wasm.DeadLetterReason.AttemptsExhausted:
      return 'attemptsExhausted';
    case wasm.DeadLetterReason.ContentUnrecoverable:
      return 'contentUnrecoverable';
    case wasm.DeadLetterReason.BaseSuperseded:
      return 'baseSuperseded';
    case wasm.DeadLetterReason.HeadTooLarge:
      return 'headTooLarge';
    case wasm.DeadLetterReason.PreservationRefused:
      return 'preservationRefused';
    case wasm.DeadLetterReason.AlreadyPublished:
      return 'alreadyPublished';
    case wasm.DeadLetterReason.TargetStillLinked:
      return 'targetStillLinked';
    case wasm.DeadLetterReason.ScopeRootNotResealable:
      return 'scopeRootNotResealable';
    case wasm.DeadLetterReason.BinIndexFull:
      return 'binIndexFull';
    case wasm.DeadLetterReason.CrossingUnauthorable:
      return 'crossingUnauthorable';
    case wasm.DeadLetterReason.BinIndexStrandedMint:
      return 'binIndexStrandedMint';
    default:
      // Fail closed: an unmapped (or absent) value means a JS/WASM version
      // mismatch, not a dead letter safe to report without its reason.
      throw new Error(`unknown WASM dead letter reason value: ${reason}`);
  }
}

function blockedHold(blocked: WasmBlockedOp | undefined): BlockedOpDescriptor | null {
  if (blocked === undefined) return null;
  return {
    opId: blocked.opId,
    node: blocked.node,
    neededBytes: blocked.neededBytes,
  };
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

export function readEvent(wasm: EngineWasm, event: WasmEvent): EventDescriptor {
  switch (event.kind) {
    case 'snapshotUpdated':
      return { kind: 'snapshotUpdated' };
    case 'stalenessChanged':
      return {
        kind: 'stalenessChanged',
        staleness: staleness(wasm, event.staleness ?? wasm.Staleness.Fresh),
      };
    case 'withheldUpdateEscalation':
      return { kind: 'withheldUpdateEscalation', ipnsName: event.ipnsName ?? new Uint8Array() };
    case 'deadLetter':
      return {
        kind: 'deadLetter',
        opId: event.opId ?? 0n,
        reason: deadLetterReason(wasm, event.deadLetterReason),
      };
    case 'parkedWritesUnreadable':
      return { kind: 'parkedWritesUnreadable' };
    case 'attributableAbuse':
      return { kind: 'attributableAbuse', description: event.description ?? '' };
    case 'renewalFailed':
      return {
        kind: 'renewalFailed',
        routingKey: event.routingKey ?? '',
        detail: event.detail ?? '',
      };
    case 'vaultUnprovisioned':
      return {
        kind: 'vaultUnprovisioned',
        retryable: event.retryable ?? false,
        detail: event.detail ?? '',
      };
    case 'opProgress':
      return {
        kind: 'opProgress',
        opId: event.opId ?? null,
        node: event.node ?? new Uint8Array(),
        phase: opPhase(wasm, event.phase),
        blocksConfirmed: event.blocksConfirmed ?? null,
        blocksTotal: event.blocksTotal ?? null,
        error: event.error ?? null,
      };
    default:
      // Fail closed: an unmapped kind means a JS/WASM version mismatch, not a
      // safe-to-ignore event (the event pump turns this throw into a fatal).
      throw new Error(`unknown WASM event kind: ${event.kind}`);
  }
}

/** Reads a wasm-bindgen `SnapshotView`'s key-free getters into a descriptor. */
export function readSnapshot(wasm: EngineWasm, view: WasmSnapshotView): SnapshotDescriptor {
  return {
    root: view.root,
    folder: view.folder,
    folderName: view.folderName,
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
    })),
    ancestors: view.ancestors.map((ancestor) => ({ id: ancestor.id, name: ancestor.name })),
    deadLetters: view.deadLetters.map((dead) => ({
      opId: dead.opId,
      reason: deadLetterReason(wasm, dead.reason),
    })),
    blocked: blockedHold(view.blocked),
    retainedRecords: view.retainedRecords,
    staleness: staleness(wasm, view.staleness),
  };
}

function pinModeFrom(wasm: EngineWasm, mode: number): PinMode {
  switch (mode) {
    case wasm.PinMode.Hosted:
      return 'hosted';
    case wasm.PinMode.External:
      return 'external';
    case wasm.PinMode.Dual:
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
    case wasm.ByoKind.Kubo:
      return 'kubo';
    case wasm.ByoKind.Psa:
      return 'psa';
    case wasm.ByoKind.Pinata:
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
    case wasm.Permission.Read:
      return 'read';
    case wasm.Permission.Write:
      return 'write';
    default:
      // Fail closed: an unmapped value means a JS/WASM version mismatch, and a
      // guessed permission would misreport who can write to a scope.
      throw new Error(`unknown WASM permission value: ${permission}`);
  }
}

/**
 * The four verdicts `ResolutionClass::name` produces, and nothing else: an
 * unmapped string is a JS/WASM version mismatch, and guessing one would paint a
 * revoked share as still granted.
 */
function resolution(name: string | undefined): ReceivedShareResolution | null {
  switch (name) {
    case undefined:
      return null;
    case 'granted':
    case 'revocation-signal':
    case 'unresolvable':
    case 'epoch-lag':
      return name;
    default:
      throw new Error(`unknown WASM resolution class: ${name}`);
  }
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
  const links = state?.inviteLinks;
  return {
    scope: view.scope,
    contacts: view.contacts.map((contact) => ({
      identityPublicKey: contact.identityPublicKey,
    })),
    ownContactCode: view.ownContactCode,
    state:
      state === undefined
        ? null
        : {
            grants: state.grants.map((grant) => ({
              recipientIdentityPublicKey: grant.recipientIdentityPublicKey,
              permission: permissionFrom(wasm, grant.permission),
            })),
            grantRefusal: state.grantRefusal ?? null,
            inviteLinkRefusal: state.inviteLinkRefusal ?? null,
            inviteLinks:
              links === undefined
                ? null
                : {
                    live: links.live,
                    expired: links.expired,
                    expiresAt: links.expiresAt ?? null,
                    spent: links.spent,
                  },
          },
  };
}
