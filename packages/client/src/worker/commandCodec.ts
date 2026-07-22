/**
 * Translates between the plain-data wire protocol and the wasm-bindgen facade
 * types, inside the engine worker realm.
 *
 * `buildCommand` rebuilds a real `Command` from a descriptor via the generated
 * builders; `readEvent` reads a `Event`'s key-free getters into a descriptor.
 * No interpretation, no crypto — the engine below the facade owns all of that.
 */

import type {
  CommandDescriptor,
  EventDescriptor,
  NodeKind,
  Permission,
  Staleness,
} from './protocol.js';
import type { EngineWasm, WasmCommand, WasmEvent, WasmNodeId } from './engineWasm.js';

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
        nodeKind(wasm, descriptor.nodeKind),
        // The builder copies into WASM memory synchronously; a view over the
        // transferred content buffer is safe (no await between here and the copy).
        descriptor.content === null ? undefined : new Uint8Array(descriptor.content)
      );
    case 'delete':
      return wasm.Command.delete(nodeId(wasm, descriptor.node));
    case 'rename':
      return wasm.Command.rename(nodeId(wasm, descriptor.node), descriptor.newName);
    case 'relink':
      return wasm.Command.relink(nodeId(wasm, descriptor.node), nodeId(wasm, descriptor.newParent));
    case 'updateContent':
      return wasm.Command.updateContent(
        nodeId(wasm, descriptor.node),
        new Uint8Array(descriptor.content)
      );
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
      return { kind: 'deadLetter', opId: event.opId ?? 0n };
    case 'attributableAbuse':
      return { kind: 'attributableAbuse', description: event.description ?? '' };
    default:
      // Fail closed: an unmapped kind means a JS/WASM version mismatch, not a
      // safe-to-ignore event (the event pump turns this throw into a fatal).
      throw new Error(`unknown WASM event kind: ${event.kind}`);
  }
}
