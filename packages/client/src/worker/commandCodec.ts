/**
 * The worker's side of the WASM seam, inside the engine worker realm: the
 * checkers for the request fields a read or a write handle carries, and the
 * fail-closed read of each enum value in an event or a view. No
 * interpretation, no crypto — the engine below the facade owns all of that.
 */

import { MAX_FRAGMENT_CHARS } from './protocol.js';
import type {
  AuthMethodDescriptor,
  AuthMethodKind,
  BinDescriptor,
  BinIndexHoldCheck,
  BinOriginDescriptor,
  ByoKind,
  DeadLetterReason,
  DeviceRendezvousResult,
  DropCause,
  EventDescriptor,
  GranteeNameSource,
  InvitePreviewDescriptor,
  InvitePreviewState,
  NodeKind,
  OpProgressPhase,
  OwedWorkClass,
  PendingClass,
  Permission,
  PinMode,
  QueueHoldDescriptor,
  ReceivedShareDescriptor,
  ReceivedShareResolution,
  ReclaimStallReason,
  SettingsHoldCheck,
  SettingsOrigin,
  SharingDescriptor,
  SnapshotDescriptor,
  Staleness,
  VaultStorageDescriptor,
} from './protocol.js';
import type { EngineWasm, WasmNodeId } from './engineWasm.js';

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
  rotationWorkOwed: true,
  rotationWorkAbandoned: true,
  nodeDropped: true,
  writeCutUnfinished: true,
  granteeJoined: true,
  opProgress: true,
};

const RENDEZVOUS_RESULT_KINDS: Record<DeviceRendezvousResult['kind'], true> = {
  opened: true,
  response: true,
  factor: true,
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

const NODE_KINDS: Record<NodeKind, true> = { file: true, folder: true };

const PENDING_CLASSES: Record<PendingClass, true> = { none: true, metadata: true, content: true };

const PERMISSIONS: Record<Permission, true> = { read: true, write: true };

const GRANTEE_NAME_SOURCES: Record<GranteeNameSource, true> = { owner: true, claimant: true };

const SETTINGS_HOLD_CHECKS: Record<SettingsHoldCheck, true> = {
  'byo-endpoint-invalid': true,
  'byo-endpoint-insecure': true,
  'byo-endpoint-blocked': true,
  'byo-credential-invalid': true,
  'byo-credential-unresolved': true,
  'byo-credential-not-stored': true,
  'byo-credential-repointed': true,
  'byo-provider-missing': true,
  'byo-no-external-ingress': true,
  'stranded-mint': true,
  'revision-rolled-back': true,
  expired: true,
  unreadable: true,
};

const BIN_INDEX_HOLD_CHECKS: Record<BinIndexHoldCheck, true> = {
  'unproven-first-run': true,
  suppressed: true,
  expired: true,
  'timed-out': true,
  'floor-unreadable': true,
};

const RESOLUTIONS: Record<ReceivedShareResolution, true> = {
  granted: true,
  'revocation-signal': true,
  unresolvable: true,
  'epoch-lag': true,
  expired: true,
};

const PREVIEW_STATES: Record<InvitePreviewState, true> = {
  live: true,
  expired: true,
  revoked: true,
  unresolvable: true,
};

const BIN_ORIGIN_KINDS: Record<BinOriginDescriptor['kind'], true> = {
  root: true,
  folder: true,
  gone: true,
};

const SETTINGS_ORIGINS: Record<SettingsOrigin, true> = {
  resolved: true,
  stale: true,
  defaults: true,
};

const PIN_MODES: Record<PinMode, true> = { hosted: true, external: true, dual: true };

const BYO_KINDS: Record<ByoKind, true> = { kubo: true, psa: true, pinata: true };

const STALL_REASONS: Record<ReclaimStallReason, true> = {
  nodeUnreadable: true,
  targetStillLive: true,
  targetUnexpandable: true,
};

const OWED_WORK_CLASSES: Record<OwedWorkClass, true> = {
  availability: true,
  capability: true,
  trust: true,
};

const DROP_CAUSES: Record<DropCause, true> = {
  'record-refused': true,
  'epoch-unreachable': true,
  'no-record': true,
  'endpoint-unavailable': true,
  'no-head-block': true,
  'below-sequence-floor': true,
  'epoch-above-root': true,
};

const AUTH_METHOD_KINDS: Record<AuthMethodKind, true> = {
  identity: true,
  wallet: true,
  test: true,
  unknown: true,
};

/**
 * Refuses a value this build does not know. An unknown value means a JS/WASM
 * version mismatch, never a state safe to render as a guess: a guessed
 * permission would misreport who can write, a guessed verdict would paint a
 * revoked share as granted. The event pump turns the throw into a fatal; a
 * read rejects.
 */
function known(values: Record<string, true>, value: unknown, what: string): void {
  if (typeof value !== 'string' || !Object.hasOwn(values, value)) {
    throw new Error(`unknown WASM ${what}: ${String(value)}`);
  }
}

/** As [`known`], with `null` passing for a value the engine did not project. */
function knownOrNull(values: Record<string, true>, value: unknown, what: string): void {
  if (value !== null) known(values, value, what);
}

/**
 * Passes an engine event through once its kind and each enum value in it are
 * ones this build knows.
 */
export function readEvent(event: EventDescriptor): EventDescriptor {
  known(EVENT_KINDS, event.kind, 'event kind');
  if (event.kind === 'stalenessChanged') known(STALENESS, event.staleness, 'staleness');
  if (event.kind === 'deadLetter') known(DEAD_LETTER_REASONS, event.reason, 'dead letter reason');
  if (event.kind === 'opProgress') known(OP_PHASES, event.phase, 'op phase');
  if (event.kind === 'rotationWorkOwed') known(OWED_WORK_CLASSES, event.class, 'owed work class');
  if (event.kind === 'nodeDropped') known(DROP_CAUSES, event.cause, 'drop cause');
  return event;
}

/** Passes a rendezvous result through once its kind is one this build knows. */
export function readRendezvous(result: DeviceRendezvousResult): DeviceRendezvousResult {
  known(RENDEZVOUS_RESULT_KINDS, result.kind, 'rendezvous result kind');
  return result;
}

/**
 * Refuses a held queue head whose reason or check name this build does not
 * know. A hold whose cause cannot be named would render as an unexplained
 * stall, which is the state the hold exists to remove.
 */
function checkQueueHold(hold: QueueHoldDescriptor | null): void {
  if (hold === null) return;
  switch (hold.reason) {
    case 'quota':
      break;
    case 'settings':
      known(SETTINGS_HOLD_CHECKS, hold.check, 'settings hold check');
      break;
    case 'bin-index':
      known(BIN_INDEX_HOLD_CHECKS, hold.check, 'bin-index hold check');
      break;
    default:
      throw new Error(`unknown WASM queue hold reason: ${(hold as { reason: unknown }).reason}`);
  }
}

/** Passes a snapshot through once each enum value in it is one this build knows. */
export function readSnapshot(view: SnapshotDescriptor): SnapshotDescriptor {
  known(PERMISSIONS, view.permission, 'permission');
  known(STALENESS, view.staleness, 'staleness');
  for (const child of view.children) {
    known(NODE_KINDS, child.kind, 'node kind');
    known(PENDING_CLASSES, child.pending, 'pending class');
  }
  for (const dead of view.deadLetters) {
    known(DEAD_LETTER_REASONS, dead.reason, 'dead letter reason');
  }
  checkQueueHold(view.queueHold);
  return view;
}

/** Passes a sharing view through once each enum value in it is one this build knows. */
export function readSharing(view: SharingDescriptor): SharingDescriptor {
  for (const grant of view.state?.grants ?? []) {
    known(PERMISSIONS, grant.permission, 'permission');
    if (grant.granteeName !== null) {
      known(GRANTEE_NAME_SOURCES, grant.granteeName.source, 'grantee name source');
    }
  }
  for (const link of view.state?.inviteLinks ?? []) {
    known(PERMISSIONS, link.permission, 'permission');
  }
  return view;
}

/** Passes the received shares through once each verdict is one this build knows. */
export function readReceivedShares(rows: ReceivedShareDescriptor[]): ReceivedShareDescriptor[] {
  for (const row of rows) {
    known(PERMISSIONS, row.permission, 'permission');
    knownOrNull(RESOLUTIONS, row.resolution, 'resolution class');
  }
  return rows;
}

/** Passes an invite preview through once its state and kinds are ones this build knows. */
export function readInvitePreview(preview: InvitePreviewDescriptor): InvitePreviewDescriptor {
  knownOrNull(PERMISSIONS, preview.permission, 'permission');
  known(PREVIEW_STATES, preview.state, 'invite preview state');
  for (const entry of preview.listing) {
    known(NODE_KINDS, entry.kind, 'node kind');
  }
  return preview;
}

/** Passes a bin view through once each enum value in it is one this build knows. */
export function readBin(view: BinDescriptor): BinDescriptor {
  known(SETTINGS_ORIGINS, view.origin, 'settings origin');
  for (const row of view.entries) {
    known(NODE_KINDS, row.kind, 'node kind');
    known(BIN_ORIGIN_KINDS, row.originFolder.kind, 'bin origin kind');
  }
  return view;
}

/** Passes a storage view through once each enum value in it is one this build knows. */
export function readVaultStorage(view: VaultStorageDescriptor): VaultStorageDescriptor {
  known(PIN_MODES, view.settings.pinMode, 'pin mode');
  knownOrNull(BYO_KINDS, view.settings.byoKind, 'provider kind');
  known(SETTINGS_ORIGINS, view.settings.origin, 'settings origin');
  for (const stall of view.reclaimStalls) {
    known(STALL_REASONS, stall.reason, 'reclaim stall reason');
  }
  return view;
}

/** Passes the login methods through once each kind is one this build knows. */
export function readAuthMethods(rows: AuthMethodDescriptor[]): AuthMethodDescriptor[] {
  for (const row of rows) {
    known(AUTH_METHOD_KINDS, row.kind, 'auth method kind');
  }
  return rows;
}
