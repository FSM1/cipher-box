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
  Permission,
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

function nodeId(wasm: EngineWasm, bytes: Uint8Array): WasmNodeId {
  return wasm.NodeId.fromBytes(bytes);
}

function nodeKind(wasm: EngineWasm, kind: NodeKind): number {
  return kind === 'file' ? wasm.NodeKind.File : wasm.NodeKind.Folder;
}

function permission(wasm: EngineWasm, level: Permission): number {
  return level === 'read' ? wasm.Permission.Read : wasm.Permission.Write;
}

export function buildCommand(wasm: EngineWasm, descriptor: CommandDescriptor): WasmCommand {
  switch (descriptor.kind) {
    case 'create':
      return wasm.Command.create(
        nodeId(wasm, descriptor.parent),
        descriptor.name,
        nodeKind(wasm, descriptor.nodeKind)
      );
    case 'delete':
      return wasm.Command.delete(nodeId(wasm, descriptor.node));
    case 'rename':
      return wasm.Command.rename(nodeId(wasm, descriptor.node), descriptor.newName);
    case 'relink':
      return wasm.Command.relink(nodeId(wasm, descriptor.node), nodeId(wasm, descriptor.newParent));
    case 'setFocus':
      return wasm.Command.setFocus(
        descriptor.node === null ? undefined : nodeId(wasm, descriptor.node)
      );
    case 'manualRefresh':
      return wasm.Command.manualRefresh();
    case 'importContact':
      return wasm.Command.importContact(descriptor.contactCode);
    case 'grant':
      return wasm.Command.grant(
        nodeId(wasm, descriptor.node),
        descriptor.recipientIdentityPublicKey,
        permission(wasm, descriptor.permission)
      );
    case 'revoke':
      return wasm.Command.revoke(
        nodeId(wasm, descriptor.node),
        descriptor.recipientIdentityPublicKey
      );
    case 'downgrade':
      return wasm.Command.downgrade(
        nodeId(wasm, descriptor.node),
        descriptor.recipientIdentityPublicKey
      );
    case 'createInviteLink':
      return wasm.Command.createInviteLink(
        nodeId(wasm, descriptor.node),
        permission(wasm, descriptor.permission)
      );
    case 'acceptShare':
      return wasm.Command.acceptShare(descriptor.sealedSharePointer);
    case 'rotateNow':
      return wasm.Command.rotateNow(nodeId(wasm, descriptor.node));
    case 'siweLogin':
      return wasm.Command.siweLogin(descriptor.message, descriptor.signature);
    case 'logout':
      return wasm.Command.logout();
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
