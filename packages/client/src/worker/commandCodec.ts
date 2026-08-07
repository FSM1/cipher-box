/**
 * Translates between the plain-data wire protocol and the wasm-bindgen facade
 * types, inside the engine worker realm.
 *
 * `buildCommand` rebuilds a real `Command` from a descriptor via the generated
 * builders; `readEvent` reads a `Event`'s key-free getters into a descriptor.
 * No interpretation, no crypto — the engine below the facade owns all of that.
 */

import type {
  BlockedOpDescriptor,
  CommandDescriptor,
  DeadLetterReason,
  EventDescriptor,
  NodeKind,
  OpProgressPhase,
  PendingClass,
  SnapshotDescriptor,
  Staleness,
} from './protocol.js';
import type {
  EngineWasm,
  WasmBlockedOp,
  WasmCommand,
  WasmEvent,
  WasmNodeId,
  WasmSnapshotView,
} from './engineWasm.js';

/**
 * A descriptor crosses a realm boundary as plain data, so its fields arrive
 * untrusted however they are typed here: a version-skewed peer can carry a
 * wrong-typed one, and wasm-bindgen would coerce it — a `12345` newName
 * marshalled as `"12345"` — rather than reject it. Every field the builders
 * read is checked, so the only wrong-typed field is a rejected command.
 */
function invalidField(field: string, value: unknown): Error {
  return new Error(`invalid command field ${field}: ${value === null ? 'null' : typeof value}`);
}

function bytes(value: unknown, field: string): Uint8Array {
  if (!(value instanceof Uint8Array)) throw invalidField(field, value);
  return value;
}

function text(value: unknown, field: string): string {
  if (typeof value !== 'string') throw invalidField(field, value);
  return value;
}

function opId(value: unknown, field: string): bigint {
  if (typeof value !== 'bigint') throw invalidField(field, value);
  return value;
}

function nodeId(wasm: EngineWasm, value: unknown, field: string): WasmNodeId {
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

export function buildCommand(wasm: EngineWasm, descriptor: CommandDescriptor): WasmCommand {
  switch (descriptor.kind) {
    case 'create':
      return wasm.Command.create(
        nodeId(wasm, descriptor.parent, 'parent'),
        text(descriptor.name, 'name'),
        nodeKind(wasm, descriptor.nodeKind)
      );
    case 'delete':
      return wasm.Command.delete(nodeId(wasm, descriptor.node, 'node'));
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
      return wasm.Command.cancelUpload(opId(descriptor.opId, 'opId'));
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
    case 'createInviteLink':
      return wasm.Command.createInviteLink(
        nodeId(wasm, descriptor.node, 'node'),
        permission(wasm, descriptor.permission)
      );
    case 'acceptShare':
      return wasm.Command.acceptShare(bytes(descriptor.sealedSharePointer, 'sealedSharePointer'));
    case 'rotateNow':
      return wasm.Command.rotateNow(nodeId(wasm, descriptor.node, 'node'));
    case 'siweLogin':
      return wasm.Command.siweLogin(
        text(descriptor.message, 'message'),
        bytes(descriptor.signature, 'signature')
      );
    case 'logout':
      return wasm.Command.logout();
    default: {
      // Fail closed: an unmapped kind means a peer built against a different
      // protocol, not a command to guess at. The `never` binding makes adding
      // a kind without a builder a compile error.
      const unmapped: never = descriptor;
      throw new Error(`unknown command kind: ${String((unmapped as CommandDescriptor).kind)}`);
    }
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
    case 'attributableAbuse':
      return { kind: 'attributableAbuse', description: event.description ?? '' };
    case 'renewalFailed':
      return {
        kind: 'renewalFailed',
        routingKey: event.routingKey ?? '',
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
