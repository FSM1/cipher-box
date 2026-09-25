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

/**
 * The most fragment characters any hop carries. A guard, not the contract — the
 * engine's own bound is what a fragment answers to — and it belongs here so the
 * sender refuses an oversize link before a structured clone puts it in another
 * realm's heap.
 */
export const MAX_FRAGMENT_CHARS = 4096;

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
  | 'headTooLarge'
  | 'preservationRefused'
  | 'alreadyPublished'
  | 'targetStillLinked'
  | 'scopeRootNotResealable'
  | 'binIndexFull'
  | 'crossingUnauthorable'
  | 'binIndexStrandedMint'
  | 'targetLinkedAcrossScopes'
  | 'graftedScopeVaultSurface';

/** A terminal dead-lettered op and its reason, as data. */
export interface DeadLetterDescriptor {
  opId: bigint;
  reason: DeadLetterReason;
}

/**
 * The rule that refused the member's own settings, as the engine's stable check
 * names. Only the verdicts a settings hold can carry: a hold waits on the member
 * changing something, so a provider's own answer is retried rather than held.
 */
export const SETTINGS_HOLD_CHECKS = [
  'byo-endpoint-invalid',
  'byo-endpoint-insecure',
  'byo-endpoint-blocked',
  'byo-credential-invalid',
  'byo-provider-missing',
  'byo-no-external-ingress',
] as const;

export type SettingsHoldCheck = (typeof SETTINGS_HOLD_CHECKS)[number];

/**
 * What a bin index load produced, as the engine's stable check names. Only the
 * outcomes a bin index hold can carry: a refusal of bytes the plane served is
 * charged as an attempt, and a stranded mint dead-letters.
 */
export const BIN_INDEX_HOLD_CHECKS = [
  'unproven-first-run',
  'suppressed',
  'expired',
  'timed-out',
  'floor-unreadable',
] as const;

export type BinIndexHoldCheck = (typeof BIN_INDEX_HOLD_CHECKS)[number];

/** The held op and the node it targets, which every hold reason carries. */
interface HeldQueueHead {
  opId: bigint;
  node: Uint8Array;
}

/** The queue head held over the account quota. */
export interface QuotaHoldDescriptor extends HeldQueueHead {
  reason: 'quota';
  neededBytes: bigint;
}

/**
 * The queue head held over the member's own settings. The check names the rule,
 * never the endpoint or the bearer those settings carry.
 */
export interface SettingsHoldDescriptor extends HeldQueueHead {
  reason: 'settings';
  check: SettingsHoldCheck;
}

/** The queue head held over the owner's bin index. */
export interface BinIndexHoldDescriptor extends HeldQueueHead {
  reason: 'bin-index';
  check: BinIndexHoldCheck;
}

/**
 * The one held queue head, as data (mirrors the facade `QueueHold`). One head
 * is held for one reason, so a host dispatches on `reason` rather than reading
 * parallel fields.
 */
export type QueueHoldDescriptor =
  | QuotaHoldDescriptor
  | SettingsHoldDescriptor
  | BinIndexHoldDescriptor;

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
  /** The head version's content root CID; `null` until projected. */
  contentCid: Uint8Array | null;
  /**
   * Invite claims that wait for `convertInviteClaims` at this scope root. Zero
   * on a device that holds no record of the link they claim.
   */
  pendingInviteClaims: number;
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
  /**
   * What this vault may do now in the scope the listed folder belongs to. Every
   * scope of this vault's own is `write`. A received share is `write` only under
   * a write grant the engine has proved, and `read` otherwise. A host refuses a
   * write at the gesture on this, rather than leaving the drain to refuse it.
   */
  permission: Permission;
  /**
   * Whether the listed folder stands in a scope another vault granted this one.
   * A write there stays inside that scope, so a host offers no share, version
   * restore or version delete where this reads true.
   */
  receivedShare: boolean;
  children: SnapshotChildDescriptor[];
  ancestors: BreadcrumbDescriptor[];
  deadLetters: DeadLetterDescriptor[];
  /** The drain's held queue head, or `null` when nothing is held. */
  queueHold: QueueHoldDescriptor | null;
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
  /** The last grantee name this device saw for the peer: a pre-fill, never an authority. */
  cachedName: string | null;
}

/** Who chose a grantee name on the owner-signed row. */
export type GranteeNameSource = 'owner' | 'claimant';

/** One grant a scope's ledger commits, as data (mirrors `SharingGrant`). */
export interface SharingGrantDescriptor {
  /** Joins the row to a contact by identity key. */
  recipientIdentityPublicKey: Uint8Array;
  permission: Permission;
  /** The name on the owner-attested row; `null` where the row carries none. */
  granteeName: { name: string; source: GranteeNameSource } | null;
}

/**
 * One invite link this owner's commitment carries at a scope, as data (mirrors
 * `SharingInviteLink`). Never the capability: the engine hands out a link's
 * fragment once, at the mint.
 */
export interface SharingInviteLinkDescriptor {
  /** The link entry's blinded tag, which `revokeInviteLink` names to cut this link. */
  tag: Uint8Array;
  /** What a conversion grants a claimant of this link. */
  permission: Permission;
  /** The owner-signed Unix-millis deadline. */
  expiresAt: bigint;
  /** The deadline has passed, as the engine's own clock reads it. */
  expired: boolean;
  /** The owner-signed admission cap. */
  admissionCap: number;
  /** Invite claims this link signed that wait for `convertInviteClaims`. */
  pendingClaims: number;
  /** This link's claims hold its whole contact share, so none converts until a revoke. */
  contactBudgetFull: boolean;
}

/** What one scope's own record says, as data (mirrors `ScopeSharing`). */
export interface ScopeSharingDescriptor {
  grants: SharingGrantDescriptor[];
  /**
   * The refusal a contact grant here would report, or `null` where none of the
   * grounds this read consults stands in the way — a command may still refuse on
   * one it does not, so this narrows what a host offers rather than promising a
   * command will be accepted. The engine's own check name either way, so the
   * host re-derives no rule of its own.
   */
  grantRefusal: string | null;
  /** The refusal an invite-link mint here would report, or `null`. */
  inviteLinkRefusal: string | null;
  /** Every invite link this owner's commitment carries here, expired ones included. */
  inviteLinks: SharingInviteLinkDescriptor[];
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
  /** This member's own contact code, for a peer to import. Public material. */
  ownContactCode: Uint8Array;
  /** `null` when the read could not reach the scope root — see `SharingView`. */
  state: ScopeSharingDescriptor | null;
}

/**
 * The engine's verdict on a received share's latest resolve (mirrors
 * `ResolutionClass`). Only the engine reaches one — a host renders it.
 */
export type ReceivedShareResolution =
  | 'granted'
  | 'revocation-signal'
  | 'expired'
  | 'unresolvable'
  | 'epoch-lag';

/**
 * One share this vault accepted, as data (mirrors `ReceivedShareRow`).
 * A wire projection of view state the engine owns, not the forbidden
 * hand-mirrored type surface — the wasm-bindgen `.d.ts` stays the contract.
 */
export interface ReceivedShareDescriptor {
  /** The shared scope — this row's stable identity, and what a browse opens. */
  scope: Uint8Array;
  /** Joins the row to a contact by identity key. */
  sharerIdentityPublicKey: Uint8Array;
  displayName: string;
  permission: Permission;
  /** `null` when no pass has resolved this share yet — never "still granted". */
  resolution: ReceivedShareResolution | null;
  /** The share reads through the link it was joined by, so a revocation signal is the link's revoke. */
  viaLink: boolean;
}

/** Where an invite link stands, as its preview read it (mirrors `LinkPreviewState`). */
export type InvitePreviewState = 'live' | 'expired' | 'revoked' | 'unresolvable';

/** One direct child of a previewed folder: a name and a kind, nothing else. */
export interface InvitePreviewEntryDescriptor {
  name: string;
  kind: NodeKind;
}

/**
 * What the invite page shows before the join (mirrors `InvitePreview`). The
 * preview posts nothing and persists nothing.
 */
export interface InvitePreviewDescriptor {
  /** `null` when the owner signature over the names does not verify; the link still works. */
  names: { ownerName: string; folderName: string } | null;
  /** The permission conversion grants, or `null` when no link entry was read. */
  permission: Permission | null;
  state: InvitePreviewState;
  /** This account already joined the folder: a host offers "open folder", not "join". */
  joined: boolean;
  /** Empty unless `state` is `'live'`. */
  listing: InvitePreviewEntryDescriptor[];
}

/**
 * Where a bin row's origin folder stands in the vault (mirrors the facade
 * `BinOrigin`). `'gone'` is the state a default restore refuses on, so a host
 * names it rather than showing a folder that is not there.
 */
export type BinOriginDescriptor =
  | { kind: 'root' }
  | { kind: 'folder'; name: string }
  | { kind: 'gone' };

/** One soft-deleted node, as data (mirrors the facade `BinRow`). */
export interface BinRowDescriptor {
  node: Uint8Array;
  kind: NodeKind;
  /** The folder the node was unlinked from, where a restore puts it back. */
  originParent: Uint8Array;
  originName: string;
  /** That folder as a member reads it, rather than as a node id. */
  originFolder: BinOriginDescriptor;
  /** Deletion time in Unix millis; a host renders expiry from it. */
  deletedAt: bigint;
  scope: Uint8Array;
}

/**
 * The `/bin` route's whole read, as data (mirrors the facade `BinView`).
 * A wire projection of view state the engine owns, not the forbidden
 * hand-mirrored type surface — the wasm-bindgen `.d.ts` stays the contract.
 */
export interface BinDescriptor {
  entries: BinRowDescriptor[];
  /**
   * `'defaults'` means this device established no bin index, so an empty
   * `entries` is the fallback and not a read: a surface must render that apart
   * from a bin it read.
   */
  origin: SettingsOrigin;
}

/** Where a version's bytes are pinned (mirrors the facade `PinMode`). */
export type PinMode = 'hosted' | 'external' | 'dual';

/** The kind of member-supplied IPFS provider (mirrors the facade `ByoKind`). */
export type ByoKind = 'kubo' | 'psa' | 'pinata';

/** The `accessToken` value that keeps the bearer the engine already holds. */
export const KEEP_STORED_BEARER = 'keep';

/** A member's own IPFS provider, as data. */
export interface ByoIpfsConfigDescriptor {
  endpoint: string;
  kind: ByoKind;
  /**
   * Bearer credential, three-state: a buffer sets a new one, `'keep'` keeps
   * whatever the engine already holds, and `null` stores none. `'keep'` is the
   * only way a host that can never read a stored bearer back leaves one alone.
   *
   * A transferable buffer rather than a string, which cannot be overwritten:
   * every hop moves it ([`commandTransfer`]), so the receiving realm is the
   * only holder left and is the terminal owner that scrubs it.
   */
  accessToken: ArrayBuffer | typeof KEEP_STORED_BEARER | null;
}

/** The member's placement, provider and retention choice, as data. */
export interface VaultSettingsDescriptor {
  pinMode: PinMode;
  byo: ByoIpfsConfigDescriptor | null;
  /** Newest-n retention; `null` keeps every version within quota. */
  keepLatestVersions: number | null;
  /**
   * Days a soft-deleted node stays in the bin; `0` keeps the hard delete.
   * Absent takes the engine's documented default.
   */
  binRetentionDays?: number | null;
}

/** Whose choice a settings summary reports (mirrors the facade `SettingsOrigin`). */
export type SettingsOrigin = 'resolved' | 'stale' | 'defaults';

/**
 * The member's settings as a host may see them, as data. The provider
 * credential is absent by construction — the wasm boundary exists to keep it
 * uncrossable.
 */
export interface VaultSettingsSummaryDescriptor {
  pinMode: PinMode;
  byoEndpoint: string | null;
  byoKind: ByoKind | null;
  /** Whether a provider bearer is stored. The bearer itself never crosses. */
  byoCredentialStored: boolean;
  /** `null` keeps every version within quota. */
  keepLatestVersions: number | null;
  /** Days a soft-deleted node stays in the bin; `0` keeps the hard delete. */
  binRetentionDays: number;
  origin: SettingsOrigin;
}

/** Why a reclaim debt did not settle (mirrors the facade `ReclaimStallReason`). */
export type ReclaimStallReason = 'nodeUnreadable' | 'targetStillLive' | 'targetUnexpandable';

/** One debt a reclaim pass left owed, as data (mirrors `ReclaimStall`). */
export interface ReclaimStallDescriptor {
  node: Uint8Array;
  /** The doomed version's root `contentCid`. */
  target: string;
  reason: ReclaimStallReason;
}

/** The account's hosted-storage figures, as data (mirrors the facade `QuotaView`). */
export interface QuotaDescriptor {
  usedBytes: number;
  limitBytes: number;
  /** True where the figure is a hint rather than a ceiling. */
  advisory: boolean;
}

/**
 * The storage pane's whole read, as data (mirrors the facade `VaultStorageView`).
 * A wire projection of view state the engine owns, not the forbidden
 * hand-mirrored type surface — the wasm-bindgen `.d.ts` stays the contract.
 */
export interface VaultStorageDescriptor {
  settings: VaultSettingsSummaryDescriptor;
  /** `null` when the quota probe did not answer. */
  quota: QuotaDescriptor | null;
  pendingReclaimBytes: number;
  /**
   * True when `pendingReclaimBytes` is a floor on the debt rather than its
   * total: the last reclaim pass read a bounded window of the retire ledger.
   */
  pendingReclaimIsPartial: boolean;
  reclaimStalls: ReclaimStallDescriptor[];
}

/** What established a login method (mirrors the facade `AuthMethodKind`). */
export type AuthMethodKind = 'identity' | 'wallet' | 'test' | 'unknown';

/**
 * One login method on the account, as data (mirrors the facade `AuthMethod`).
 * Display form only: the identifier hash never crosses.
 */
export interface AuthMethodDescriptor {
  id: string;
  kind: AuthMethodKind;
  identifierDisplay: string | null;
  createdAt: string;
  lastUsedAt: string | null;
}

/**
 * One device identity key on the account registry, as data (mirrors the facade
 * `RegisteredDevice`). The label is context the device chose, never evidence
 * (ADR 0009 D4).
 */
export interface RegisteredDeviceDescriptor {
  id: string;
  publicKey: string;
  label: string | null;
  createdAt: string;
  lastSeenAt: string;
}

/** One rendezvous this account is asked to approve, as data. */
export interface PendingApprovalDescriptor {
  requestId: string;
  requesterDevicePublicKey: string;
  ephemeralPublicKey: string;
  comparisonValue: string;
  createdAt: string;
  expiresAt: string;
}

/** How an approver answered one rendezvous (mirrors the facade `ApprovalDecision`). */
export type ApprovalDecision = 'approve' | 'deny';

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

/**
 * One write intent, as data. Each variant's `kind` matches the facade command
 * builder name (`crates/wasm` `Command`), so the worker maps it mechanically.
 */
export type CommandDescriptor =
  | { kind: 'create'; parent: Uint8Array; name: string; nodeKind: NodeKind }
  | { kind: 'delete'; node: Uint8Array }
  | {
      kind: 'restore';
      node: Uint8Array;
      /** `null` takes the folder the bin entry names. */
      into: Uint8Array | null;
    }
  | { kind: 'purge'; node: Uint8Array }
  | { kind: 'rename'; node: Uint8Array; newName: string }
  | { kind: 'relink'; node: Uint8Array; newParent: Uint8Array }
  | { kind: 'restoreVersion'; node: Uint8Array; contentCid: Uint8Array }
  | { kind: 'deleteVersion'; node: Uint8Array; contentCid: Uint8Array }
  | { kind: 'cancelUpload'; opId: bigint }
  | { kind: 'discardDeadLetter'; opId: bigint }
  | { kind: 'recoverDeadLetter'; opId: bigint }
  | { kind: 'setFocus'; node: Uint8Array | null }
  | { kind: 'manualRefresh' }
  | { kind: 'importContact'; contactCode: Uint8Array }
  | {
      kind: 'grant';
      node: Uint8Array;
      recipientIdentityPublicKey: Uint8Array;
      permission: Permission;
      /** The name the owner gives the grantee on the row; `null` leaves it unnamed. */
      granteeName: string | null;
    }
  | { kind: 'revoke'; node: Uint8Array; recipientIdentityPublicKey: Uint8Array }
  | {
      kind: 'changePermission';
      node: Uint8Array;
      recipientIdentityPublicKey: Uint8Array;
      permission: Permission;
    }
  | {
      kind: 'renameGrantee';
      node: Uint8Array;
      recipientIdentityPublicKey: Uint8Array;
      name: string;
    }
  | {
      kind: 'createInviteLink';
      node: Uint8Array;
      permission: Permission;
      /** Unix-millis deadline; `null` takes the engine's default lifetime. */
      expiresAt: bigint | null;
      /** Shown to the holder, signed by the owner; the engine bounds it, empty is allowed. */
      ownerName: string;
    }
  /** A `null` tag cuts the scope's only link; the engine refuses it where the scope carries more. */
  | { kind: 'revokeInviteLink'; node: Uint8Array; linkTag: Uint8Array | null }
  /**
   * The fragment is the whole bearer capability, opaque above the engine: it
   * crosses verbatim, is never parsed, and never reaches a log or any durable
   * store on the way. Length-bounded by [`MAX_FRAGMENT_CHARS`].
   */
  | { kind: 'claimInviteLink'; fragment: string }
  | { kind: 'convertInviteClaims'; node: Uint8Array }
  | { kind: 'rotateNow'; node: Uint8Array }
  | { kind: 'saveVaultSettings'; settings: VaultSettingsDescriptor }
  /** Links a host-collected wallet signature to the account already signed in. */
  | { kind: 'siweLink'; message: string; signature: Uint8Array }
  | { kind: 'unlinkAuthMethod'; methodId: string }
  | {
      kind: 'registerDevice';
      publicKey: string;
      signature: string;
      identityToken: string;
      label: string | null;
    }
  | { kind: 'revokeDevice'; deviceId: string }
  | {
      kind: 'respondToApproval';
      requestId: string;
      decision: ApprovalDecision;
      devicePublicKey: string;
      ephemeralPublicKey: string;
      signature: string;
      /** A denial seals nothing, so it carries `null`. */
      sealedFactor: string | null;
    }
  | { kind: 'logout' }
  | { kind: 'forgetDevice' };

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
  | { kind: 'contactImported'; identityPublicKey: Uint8Array; encPublicKey: Uint8Array }
  /** The whole bearer capability: a host puts `fragment` in a URL and hands the
   * same characters back to `claimInviteLink`, reading none of it. */
  | { kind: 'inviteLinkMinted'; fragment: string }
  /**
   * The device was forgotten. `unsettledBytes` is what the settling pass ahead
   * of the erase could not pay — pinned bytes that stay charged to the account
   * with no device left owing them — and `null` when no pass ran at all, so the
   * ledger was never read.
   */
  | ({ kind: 'forgotten' } & ForgottenResidual);

/**
 * What a forget's settling pass could not pay before the erase: pinned bytes
 * that stay charged to the account with no device left owing them.
 */
export interface ForgottenResidual {
  /** `null` when no pass ran, so the ledger was never read. */
  unsettledBytes: number | null;
  /**
   * True when that figure is a floor rather than the whole debt: the pass read
   * a bounded window of the retire ledger and left keys unattempted.
   */
  unsettledIsPartial: boolean;
  stalls: number;
}

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

/** One event the engine emitted, as data (mirrors the facade `Event`). */
export type EventDescriptor =
  | { kind: 'snapshotUpdated' }
  | { kind: 'stalenessChanged'; staleness: Staleness }
  | { kind: 'withheldUpdateEscalation'; ipnsName: Uint8Array }
  | { kind: 'deadLetter'; opId: bigint; reason: DeadLetterReason }
  /** This device holds a preserved dead-letter record another build wrote. */
  | { kind: 'parkedWritesUnreadable' }
  /** This device's grantee-name cache did not open and was cleared; names on the rows stand. */
  | { kind: 'granteeNamesCleared' }
  | { kind: 'attributableAbuse'; description: string }
  | { kind: 'renewalFailed'; routingKey: string; detail: string }
  | { kind: 'vaultUnprovisioned'; retryable: boolean; detail: string }
  /** The engine adopted vault settings other than the ones it held; read them again. */
  | { kind: 'vaultSettingsChanged' }
  /** A scope-exit cut this device owes did not land, so the scope is uncut. */
  | { kind: 'scopeExitCutOwed'; scopeRoot: Uint8Array; detail: string }
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

/**
 * Which SIWE surface a nonce is minted for. The API keeps one challenge pool per
 * intent and refuses a cross-intent spend, so the caller names the operation the
 * wallet signature will authorise.
 */
export type SiweIntent = 'login' | 'link';

/**
 * One read intent, as data. Every read the engine serves is one member of this
 * union, so a new read costs one member and one [`ReadResults`] entry rather
 * than a hand-threaded method at each layer of the rail.
 */
/**
 * One prior version of a file. Every field comes from the file's sealed
 * read-body; the content key that rides beside them there never crosses this
 * boundary. `contentCid` is the identifier every version call takes.
 */
export interface VersionEntryDescriptor {
  contentCid: Uint8Array;
  /** The version's plaintext size in bytes. */
  size: bigint;
  /** When the version was written, Unix millis. */
  modifiedAt: bigint;
}

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
