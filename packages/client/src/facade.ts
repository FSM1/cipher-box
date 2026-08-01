/**
 * The typed async facade over the worker-hosted engine (blueprint/web-client.md
 * "Engine hosting"). One method per facade command plus cold-start (`start`) and
 * teardown (`logout`); every call is data in, a settled promise out. The facade
 * adds transport, never semantics — it wraps the engine facade, it does not
 * extend it.
 *
 * It holds no engine logic and no key material: `start` transfers the login
 * secret straight through to the worker (which zeroes its copy after the engine
 * consumes it), and events arrive as key-free view descriptors.
 */

import type { EngineEventListener, EngineTransport } from './transport.js';
import type {
  CommandDescriptor,
  NodeKind,
  Permission,
  SnapshotDescriptor,
  WriteHandle,
  WriteTarget,
} from './worker/protocol.js';

export class EngineFacade {
  constructor(private readonly transport: EngineTransport) {}

  /**
   * Cold start: hands the login secret to the engine once, transferred (the
   * caller's `secret` buffer is detached by the transfer). Resolves when the
   * engine has run its cold-start sequence (vault-pointer resolve, floor
   * cold-seed, root adoption, first snapshot event).
   */
  start(secret: ArrayBuffer): Promise<void> {
    return this.transport.start(secret);
  }

  /**
   * Logout: the engine zeroizes its WASM state, then the worker is torn down.
   * Durable seams (floors, op queue, staged bytes, ciphertext cache) survive by
   * design.
   */
  async logout(): Promise<void> {
    // Teardown is unconditional: tearing the worker down frees the WASM memory
    // (the terminal zeroization) regardless of how the engine answers the
    // zeroize command, so a rejected/unimplemented logout must not strand the
    // worker alive.
    try {
      await this.command({ kind: 'logout' });
    } catch {
      // fall through to teardown
    }
    this.transport.close();
  }

  /** Subscribes to the one-way engine event stream; returns an unsubscribe. */
  subscribe(listener: EngineEventListener): () => void {
    return this.transport.subscribe(listener);
  }

  /** Reads a key-free snapshot of `folder`, or of the vault root for `null`. */
  snapshot(folder: Uint8Array | null): Promise<SnapshotDescriptor> {
    return this.transport.snapshot(folder);
  }

  /** Downloads one file node's plaintext through the verified read pipeline. */
  download(node: Uint8Array): Promise<ArrayBuffer> {
    return this.transport.download(node);
  }

  /** Creates an empty node. File content is written through a write handle. */
  create(parent: Uint8Array, name: string, kind: NodeKind): Promise<void> {
    return this.command({ kind: 'create', parent, name, nodeKind: kind });
  }

  /**
   * Opens a streaming write of exactly `size` plaintext bytes: `{ parent, name }`
   * creates a new file, `{ node }` writes a new version of an existing one. Feed
   * the bytes with `pushChunk`, then `commitWrite` (or `abortWrite` to release
   * the reservation); peak memory stays one chunk however large the file.
   */
  beginWrite(target: WriteTarget, size: number): Promise<WriteHandle> {
    return this.transport.beginWrite(target, size);
  }

  /** Feeds the next slice to an open handle; the buffer is transferred, not copied. */
  pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void> {
    return this.transport.pushChunk(handle, chunk);
  }

  /** Closes the handle and journals its op; resolves with the durable op id. */
  commitWrite(handle: WriteHandle): Promise<bigint> {
    return this.transport.commitWrite(handle);
  }

  /** Abandons the handle, releasing its reservation and staged blocks. */
  abortWrite(handle: WriteHandle): Promise<void> {
    return this.transport.abortWrite(handle);
  }

  delete(node: Uint8Array): Promise<void> {
    return this.command({ kind: 'delete', node });
  }

  rename(node: Uint8Array, newName: string): Promise<void> {
    return this.command({ kind: 'rename', node, newName });
  }

  relink(node: Uint8Array, newParent: Uint8Array): Promise<void> {
    return this.command({ kind: 'relink', node, newParent });
  }

  /**
   * Cancel a queued upload by the op id `commitWrite` resolved with. Rejects
   * with `tooLateToCancel` once the version's record is publishing.
   */
  cancelUpload(opId: bigint): Promise<void> {
    return this.command({ kind: 'cancelUpload', opId });
  }

  setFocus(node: Uint8Array | null): Promise<void> {
    return this.command({ kind: 'setFocus', node });
  }

  manualRefresh(): Promise<void> {
    return this.command({ kind: 'manualRefresh' });
  }

  importContact(contactCode: Uint8Array): Promise<void> {
    return this.command({ kind: 'importContact', contactCode });
  }

  grant(
    node: Uint8Array,
    recipientIdentityPublicKey: Uint8Array,
    permission: Permission
  ): Promise<void> {
    return this.command({ kind: 'grant', node, recipientIdentityPublicKey, permission });
  }

  revoke(node: Uint8Array, recipientIdentityPublicKey: Uint8Array): Promise<void> {
    return this.command({ kind: 'revoke', node, recipientIdentityPublicKey });
  }

  downgrade(node: Uint8Array, recipientIdentityPublicKey: Uint8Array): Promise<void> {
    return this.command({ kind: 'downgrade', node, recipientIdentityPublicKey });
  }

  createInviteLink(node: Uint8Array, permission: Permission): Promise<void> {
    return this.command({ kind: 'createInviteLink', node, permission });
  }

  acceptShare(sealedSharePointer: Uint8Array): Promise<void> {
    return this.command({ kind: 'acceptShare', sealedSharePointer });
  }

  rotateNow(node: Uint8Array): Promise<void> {
    return this.command({ kind: 'rotateNow', node });
  }

  /** Issues the single-use nonce an EIP-4361 message must embed. */
  siweChallenge(): Promise<string> {
    return this.transport.siweChallenge();
  }

  siweLogin(message: string, signature: Uint8Array): Promise<void> {
    return this.command({ kind: 'siweLogin', message, signature });
  }

  private command(descriptor: CommandDescriptor, transfer: Transferable[] = []): Promise<void> {
    return this.transport.command(descriptor, transfer);
  }
}
