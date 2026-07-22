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
import type { CommandDescriptor, NodeKind, Permission } from './worker/protocol.js';

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

  create(
    parent: Uint8Array,
    name: string,
    kind: NodeKind,
    content: ArrayBuffer | null = null
  ): Promise<void> {
    return this.command(
      { kind: 'create', parent, name, nodeKind: kind, content },
      content === null ? [] : [content]
    );
  }

  updateContent(node: Uint8Array, content: ArrayBuffer): Promise<void> {
    return this.command({ kind: 'updateContent', node, content }, [content]);
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

  siweLogin(message: string, signature: Uint8Array): Promise<void> {
    return this.command({ kind: 'siweLogin', message, signature });
  }

  private command(descriptor: CommandDescriptor, transfer: Transferable[] = []): Promise<void> {
    return this.transport.command(descriptor, transfer);
  }
}
