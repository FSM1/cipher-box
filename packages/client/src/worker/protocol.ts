/**
 * The UI ↔ engine-worker wire protocol (blueprint/web-client.md "Engine hosting
 * and tab leadership").
 *
 * Everything here is plain structured-clone data. A command, what it answers and
 * an event are the engine's own types, generated into the wasm-bindgen `.d.ts`
 * and re-exported here under the names the hosts import; the worker hands a
 * command to the engine as it arrived, and the engine decodes it.
 *
 * `u64`s cross as `bigint`; binary payloads cross as `Uint8Array`, with file
 * content transferred as an `ArrayBuffer` so no bytes are copied through the
 * boundary (blueprint/web-client.md "Boundary hygiene"). Content never rides a
 * command: it streams chunk by chunk through a write handle.
 */

import { isBuffer } from '../buffers.js';
import type {
  ApprovalDecision,
  AuthMethod,
  AuthMethodKind,
  BinOrigin,
  BinRow,
  BinIndexHoldCheck,
  BinView,
  BlockProgress,
  Breadcrumb,
  ByoIpfsConfig,
  ByoKind,
  Command,
  CommandOutcome,
  DeadLetter,
  DeadLetterReason,
  Event,
  GranteeNameSource,
  InvitePreview,
  LinkPreviewState,
  NodeKind,
  OpPhase,
  PendingApprovalView,
  PendingClass,
  Permission,
  PinMode,
  PreviewEntry,
  QueueHold,
  QuotaView,
  ReceivedShareRow,
  ReclaimStall,
  ReclaimStallReason,
  RegisteredDevice,
  ResolutionClass,
  ScopeEpochs,
  ScopeSharing,
  SettingsHoldCheck,
  SettingsOrigin,
  SharingContact,
  SharingGrant,
  SharingInviteLink,
  SharingView,
  SiweIntent,
  SnapshotChild,
  SnapshotView,
  Staleness,
  VaultSettings,
  VaultSettingsSummary,
  VaultStorageView,
  VersionEntry,
} from '../../wasm/cipherbox_wasm.js';

export type {
  ApprovalDecision,
  AuthMethodKind,
  BlockProgress,
  ByoKind,
  DeadLetterReason,
  GranteeNameSource,
  NodeKind,
  PendingClass,
  Permission,
  PinMode,
  ReclaimStallReason,
  SettingsOrigin,
  SiweIntent,
  Staleness,
};

/**
 * The most fragment characters any hop carries. A guard, not the contract — the
 * engine's own bound is what a fragment answers to — and it belongs here so the
 * sender refuses an oversize link before a structured clone puts it in another
 * realm's heap.
 */
export const MAX_FRAGMENT_CHARS = 4096;

/**
 * The phase an `opProgress` event reports. `uploadCompleted` means the
 * version's blocks are on the network, not that its record published — the op
 * leaves the pending-op overlay when it does.
 */
export type OpProgressPhase = OpPhase;

/** One ancestor step in a snapshot's breadcrumb trail: the engine `Breadcrumb`. */
export type BreadcrumbDescriptor = Breadcrumb;

/** A terminal dead-lettered op and its reason: the engine `DeadLetter`. */
export type DeadLetterDescriptor = DeadLetter;

/**
 * The rule a settings hold waits on, and the load outcome a bin index hold
 * waits on: the engine's own check names. A hold names a rule, never the
 * endpoint or the bearer the settings carry.
 */
export type { BinIndexHoldCheck, SettingsHoldCheck };

/** The queue head held over the account quota. */
export type QuotaHoldDescriptor = Extract<QueueHold, { reason: 'quota' }>;

/** The queue head held over the member's own settings. */
export type SettingsHoldDescriptor = Extract<QueueHold, { reason: 'settings' }>;

/** The queue head held over the owner's bin index. */
export type BinIndexHoldDescriptor = Extract<QueueHold, { reason: 'bin-index' }>;

/** The one held queue head: the engine `QueueHold`. A host dispatches on `reason`. */
export type QueueHoldDescriptor = QueueHold;

/** One direct child in a snapshot: the engine `SnapshotChild`. */
export type SnapshotChildDescriptor = SnapshotChild;

/** A key-free folder snapshot: the engine `SnapshotView`. */
export type SnapshotDescriptor = SnapshotView;

/** One contact the vault's book holds: the engine `SharingContact`. */
export type SharingContactDescriptor = SharingContact;

/** One grant a scope's ledger commits: the engine `SharingGrant`. */
export type SharingGrantDescriptor = SharingGrant;

/** One invite link a scope's commitment carries: the engine `SharingInviteLink`. */
export type SharingInviteLinkDescriptor = SharingInviteLink;

/** What one scope's own record says: the engine `ScopeSharing`. */
export type ScopeSharingDescriptor = ScopeSharing;

/** The read and write epoch of one scope root's record: the engine `ScopeEpochs`. */
export type ScopeEpochsDescriptor = ScopeEpochs;

/** One scope's sharing state: the engine `SharingView`. */
export type SharingDescriptor = SharingView;

/** The engine's verdict on a received share's latest resolve. A host renders it. */
export type ReceivedShareResolution = ResolutionClass;

/** One share this vault accepted: the engine `ReceivedShareRow`. */
export type ReceivedShareDescriptor = ReceivedShareRow;

/** Where an invite link stands, as its preview read it. */
export type InvitePreviewState = LinkPreviewState;

/** One direct child of a previewed folder: a name and a kind, nothing else. */
export type InvitePreviewEntryDescriptor = PreviewEntry;

/** What the invite page shows before the join: the engine `InvitePreview`. */
export type InvitePreviewDescriptor = InvitePreview;

/** Where a bin row's origin folder stands in the vault: the engine `BinOrigin`. */
export type BinOriginDescriptor = BinOrigin;

/** One soft-deleted node: the engine `BinRow`. */
export type BinRowDescriptor = BinRow;

/** The `/bin` route's whole read: the engine `BinView`. */
export type BinDescriptor = BinView;

/** The `accessToken` value that keeps the bearer the engine already holds. */
export const KEEP_STORED_BEARER = 'keep' satisfies ByoIpfsConfig['accessToken'];

/**
 * A member's own IPFS provider. The bearer is a transferable buffer rather than
 * a string, which cannot be overwritten: every hop moves it
 * ([`commandTransfer`]), so the receiving realm is the only holder left and is
 * the terminal owner that scrubs it.
 */
export type ByoIpfsConfigDescriptor = ByoIpfsConfig;

/** The member's placement, provider and retention choice. */
export type VaultSettingsDescriptor = VaultSettings;

/** The member's settings as a host may see them: the engine `VaultSettingsSummary`. */
export type VaultSettingsSummaryDescriptor = VaultSettingsSummary;

/** One debt a reclaim pass left owed: the engine `ReclaimStall`. */
export type ReclaimStallDescriptor = ReclaimStall;

/** The account's hosted-storage figures: the engine `QuotaView`. */
export type QuotaDescriptor = QuotaView;

/** The storage pane's whole read: the engine `VaultStorageView`. */
export type VaultStorageDescriptor = VaultStorageView;

/** One login method on the account, in display form: the engine `AuthMethod`. */
export type AuthMethodDescriptor = AuthMethod;

/** One device identity key on the account registry: the engine `RegisteredDevice`. */
export type RegisteredDeviceDescriptor = RegisteredDevice;

/** One rendezvous this account is asked to approve: the engine `PendingApprovalView`. */
export type PendingApprovalDescriptor = PendingApprovalView;

/**
 * One step of the device-approval rendezvous (ADR 0009). Every step is a pure
 * function of the exchange transcript; the engine holds no state for it.
 */
export type DeviceRendezvousStep =
  | { kind: 'open'; devicePublicKey: string; scalar: Uint8Array }
  | {
      kind: 'approve';
      devicePublicKey: string;
      requestId: string;
      requesterDevicePublicKey: string;
      ephemeralPublicKey: string;
      sealScalar: Uint8Array;
      factorKey: Uint8Array;
    }
  | { kind: 'deny'; devicePublicKey: string; requestId: string; ephemeralPublicKey: string }
  | {
      kind: 'openFactor';
      sealedFactor: string;
      requestId: string;
      requesterDevicePublicKey: string;
      /** The approving device and its signature over the whole answer (D4). */
      responderDevicePublicKey: string;
      responseSignature: string;
      scalar: Uint8Array;
    };

/** What one rendezvous step produced, as data. */
export type DeviceRendezvousResult =
  | {
      kind: 'opened';
      ephemeralPublicKey: string;
      requestPayload: Uint8Array;
      comparisonValue: string;
    }
  /** A denial seals nothing, so `sealedFactor` is `null` on that answer. */
  | { kind: 'response'; sealedFactor: string | null; payload: Uint8Array }
  | { kind: 'factor'; factorKey: Uint8Array };

/** One write intent: the engine `Command`. */
export type CommandDescriptor = Command;

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
 * The secret buffers a rendezvous step or its result hands over for good, for
 * the transfer list. They move rather than being cloned, so no realm keeps a
 * copy nobody owns (AGENTS.md 7). Takes the value unvalidated: a relay reads
 * one off an untrusted port.
 *
 * An `open` step is the exception and clones: its scalar is what the requester
 * opens the sealed factor with later, so the buffer stays the caller's.
 *
 * One backing buffer is listed once, whatever number of fields view it:
 * `postMessage` refuses a transfer list that repeats one.
 */
export function rendezvousTransfer(value: unknown): Transferable[] {
  const held = value as {
    kind?: unknown;
    scalar?: unknown;
    sealScalar?: unknown;
    factorKey?: unknown;
  } | null;
  if (held?.kind === 'open') return [];
  const buffers = [held?.scalar, held?.sealScalar, held?.factorKey]
    .filter((field): field is ArrayBufferView => ArrayBuffer.isView(field))
    .map((view) => view.buffer);
  return [...new Set(buffers)] as Transferable[];
}

/**
 * What one command produced: the engine `CommandOutcome`. Holding an imported
 * contact's keys is the proof its binding signature verified.
 */
export type CommandOutcomeDescriptor = CommandOutcome;

/**
 * What a forget's settling pass could not pay before the erase: pinned bytes
 * that stay charged to the account with no device left owing them, `null` when
 * no pass ran.
 */
export type ForgottenResidual = Omit<Extract<CommandOutcome, { kind: 'forgotten' }>, 'kind'>;

/**
 * Where a streaming write lands: a new file named `name` under `parent`, or a
 * new version of the existing file `node`. Never both (the engine rejects it).
 */
export type WriteTarget =
  | { parent: Uint8Array; name: string }
  /** `expectedVersion` is the `contentCid` the caller read; omit it to take
   * the engine's own anchor derivation. */
  | { node: Uint8Array; expectedVersion?: Uint8Array };

/** An open write handle's id — the engine's `u64`, opaque to this layer. */
export type WriteHandle = bigint;

/**
 * An open read stream's id — the engine's `u64`, opaque to this layer. The
 * stream pins one content version, so every window read against the handle is a
 * slice of one authenticated object.
 */
export type StreamHandle = bigint;

/**
 * A freshly opened read stream and the plaintext size of the version it pinned.
 * The size travels with the handle because a ranged reader must frame its
 * response head against the version the stream serves, not one it measured
 * before the pin.
 */
export interface OpenedStream {
  readonly handle: StreamHandle;
  readonly size: number;
}

/** One event the engine emitted: the engine `Event`. */
export type EventDescriptor = Event;

/** One prior version of a file: the engine `VersionEntry`. */
export type VersionEntryDescriptor = VersionEntry;

/**
 * One read intent, as data. Every read the engine serves is one member of this
 * union, so a new read costs one member and one [`ReadResults`] entry rather
 * than a hand-threaded method at each layer of the rail.
 */
export type ReadDescriptor =
  | { kind: 'snapshot'; folder: Uint8Array | null }
  | { kind: 'sharing'; scope: Uint8Array | null }
  | { kind: 'receivedShares' }
  | { kind: 'invitePreview'; fragment: string }
  | { kind: 'bin' }
  | { kind: 'vaultStorage' }
  | { kind: 'authMethods' }
  | { kind: 'devices' }
  | { kind: 'deviceRegistrationChallenge'; devicePublicKey: string }
  | { kind: 'pendingApprovals' }
  | { kind: 'deviceRendezvous'; step: DeviceRendezvousStep }
  | { kind: 'identityFingerprint'; identityPublicKey: Uint8Array }
  | { kind: 'siweChallenge'; intent: SiweIntent }
  | { kind: 'download'; node: Uint8Array }
  | { kind: 'fileVersions'; node: Uint8Array }
  | { kind: 'downloadVersion'; node: Uint8Array; contentCid: Uint8Array };

/** What each read kind answers with. */
export interface ReadResults {
  snapshot: SnapshotDescriptor;
  sharing: SharingDescriptor;
  receivedShares: ReceivedShareDescriptor[];
  invitePreview: InvitePreviewDescriptor;
  bin: BinDescriptor;
  vaultStorage: VaultStorageDescriptor;
  authMethods: AuthMethodDescriptor[];
  devices: RegisteredDeviceDescriptor[];
  deviceRegistrationChallenge: Uint8Array;
  pendingApprovals: PendingApprovalDescriptor[];
  deviceRendezvous: DeviceRendezvousResult;
  identityFingerprint: string;
  siweChallenge: string;
  download: ArrayBuffer;
  fileVersions: VersionEntryDescriptor[];
  downloadVersion: ArrayBuffer;
}

/** The answer a given read descriptor resolves with. */
export type ReadResult<D extends ReadDescriptor> = ReadResults[D['kind']];

/** Any read answer, for the layers that carry one without naming its kind. */
export type ReadResultValue = ReadResults[ReadDescriptor['kind']];

/**
 * Every read kind this build serves. A relay reads a descriptor off an
 * untrusted port, so it refuses an unknown kind here rather than passing it
 * down the rail.
 */
export const READ_KINDS: ReadonlySet<string> = new Set<ReadDescriptor['kind']>([
  'snapshot',
  'sharing',
  'receivedShares',
  'invitePreview',
  'bin',
  'vaultStorage',
  'authMethods',
  'devices',
  'deviceRegistrationChallenge',
  'pendingApprovals',
  'deviceRendezvous',
  'identityFingerprint',
  'siweChallenge',
  'download',
  'fileVersions',
  'downloadVersion',
]);

/**
 * The secret buffers a read descriptor hands over for good, for the transfer
 * list of the send that carries it — a rendezvous step's scalars and factor key
 * ([`rendezvousTransfer`]). Takes the value unvalidated: a relay reads one off
 * an untrusted port.
 */
export function readTransfer(read: unknown): Transferable[] {
  const held = read as { kind?: unknown; step?: unknown } | null;
  return held?.kind === 'deviceRendezvous' ? rendezvousTransfer(held.step) : [];
}

/** A UI → worker request. `id` correlates the eventual response. */
export type WorkerRequest =
  | { type: 'start'; id: number; secret: ArrayBuffer; accountId: string }
  | { type: 'command'; id: number; command: CommandDescriptor }
  | { type: 'read'; id: number; read: ReadDescriptor }
  | { type: 'beginWrite'; id: number; target: WriteTarget; size: number }
  | { type: 'pushChunk'; id: number; handle: WriteHandle; chunk: ArrayBuffer }
  | { type: 'commitWrite'; id: number; handle: WriteHandle }
  | { type: 'abortWrite'; id: number; handle: WriteHandle }
  | { type: 'openContentStream'; id: number; node: Uint8Array }
  | { type: 'readStream'; id: number; handle: StreamHandle; offset: number; length: number }
  | { type: 'closeStream'; id: number; handle: StreamHandle };

/** A worker → UI message. */
export type WorkerMessage =
  /** The worker has instantiated the engine and is ready for requests. */
  | { type: 'ready' }
  /**
   * The correlated result of a request. A value-bearing ok response carries it:
   * the matching [`ReadResults`] entry for a `read`, the outcome for `command`,
   * the write handle for `beginWrite`, the durable op id for `commitWrite`, the
   * `OpenedStream` for `openContentStream`, and the plaintext `ArrayBuffer`
   * (transferred, not copied) for `readStream`.
   */
  | {
      type: 'response';
      id: number;
      ok: true;
      result?: ReadResultValue | CommandOutcomeDescriptor | bigint | OpenedStream;
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
