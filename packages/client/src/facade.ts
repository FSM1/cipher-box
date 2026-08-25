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

import { isBuffer, wipeBytes } from './buffers.js';
import type { EngineEventListener, EngineTransport } from './transport.js';
import type {
  CommandDescriptor,
  CommandOutcomeDescriptor,
  NodeKind,
  Permission,
  SharingDescriptor,
  SnapshotDescriptor,
  StreamHandle,
  VaultSettingsDescriptor,
  WriteHandle,
  WriteTarget,
} from './worker/protocol.js';

/** The verified contact an import produced, with its two public keys. */
export type ImportedContact = Extract<CommandOutcomeDescriptor, { kind: 'contactImported' }>;

export class EngineFacade {
  constructor(private readonly transport: EngineTransport) {}

  /**
   * Cold start: hands the login secret to the engine once, transferred (the
   * caller's `secret` buffer is detached by the transfer). `accountId` names
   * whose durable state the engine opens. Resolves when the engine has run its
   * cold-start sequence (vault-pointer resolve, floor cold-seed, root adoption,
   * first snapshot event).
   */
  start(secret: ArrayBuffer, accountId: string): Promise<void> {
    return this.transport.start(secret, accountId);
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

  /**
   * Reads the vault's verified contact book and the grants `scope`'s own record
   * commits — the vault root's for `null`.
   */
  sharing(scope: Uint8Array | null): Promise<SharingDescriptor> {
    return this.transport.sharing(scope);
  }

  /** Downloads one file node's plaintext through the verified read pipeline. */
  download(node: Uint8Array): Promise<ArrayBuffer> {
    return this.transport.download(node);
  }

  /**
   * Opens a read stream over one file node, pinned to the head content version
   * for the handle's life. Released with `closeStream`.
   */
  openContentStream(node: Uint8Array): Promise<StreamHandle> {
    return this.transport.openContentStream(node);
  }

  /** Reads one byte window of an open stream's pinned version. */
  readStream(handle: StreamHandle, offset: number, length: number): Promise<ArrayBuffer> {
    return this.transport.readStream(handle, offset, length);
  }

  /** Releases a read stream; an unknown handle is already gone. */
  closeStream(handle: StreamHandle): Promise<void> {
    return this.transport.closeStream(handle);
  }

  /** Creates an empty node. File content is written through a write handle. */
  create(parent: Uint8Array, name: string, kind: NodeKind): Promise<CommandOutcomeDescriptor> {
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

  delete(node: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'delete', node });
  }

  rename(node: Uint8Array, newName: string): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'rename', node, newName });
  }

  relink(node: Uint8Array, newParent: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'relink', node, newParent });
  }

  /**
   * Cancel a queued upload by the op id `commitWrite` resolved with. Rejects
   * with `notAnUpload` when the op carries no content, and with
   * `tooLateToCancel` once the version's record is publishing.
   */
  cancelUpload(opId: bigint): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'cancelUpload', opId });
  }

  setFocus(node: Uint8Array | null): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'setFocus', node });
  }

  manualRefresh(): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'manualRefresh' });
  }

  /**
   * Imports a contact code. Resolving with the contact's keys *is* the proof its
   * binding signature verified — the engine mints a contact no other way.
   */
  async importContact(contactCode: Uint8Array): Promise<ImportedContact> {
    const outcome = await this.command({ kind: 'importContact', contactCode });
    if (outcome.kind !== 'contactImported') {
      throw new Error(`import contact answered ${outcome.kind}`);
    }
    return outcome;
  }

  grant(
    node: Uint8Array,
    recipientIdentityPublicKey: Uint8Array,
    permission: Permission
  ): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'grant', node, recipientIdentityPublicKey, permission });
  }

  revoke(
    node: Uint8Array,
    recipientIdentityPublicKey: Uint8Array
  ): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'revoke', node, recipientIdentityPublicKey });
  }

  downgrade(
    node: Uint8Array,
    recipientIdentityPublicKey: Uint8Array
  ): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'downgrade', node, recipientIdentityPublicKey });
  }

  /** Mints an invite link; an omitted `expiresAt` mints one that never expires. */
  createInviteLink(
    node: Uint8Array,
    permission: Permission,
    expiresAt?: bigint
  ): Promise<CommandOutcomeDescriptor> {
    return this.command({
      kind: 'createInviteLink',
      node,
      permission,
      expiresAt: expiresAt ?? null,
    });
  }

  /** Revokes the link minted at `node`: future claims end, converted grants stand. */
  revokeInviteLink(node: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'revokeInviteLink', node });
  }

  /** Drops the invite records the scope's owner-signed commitment no longer carries. */
  pruneInviteLinks(node: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'pruneInviteLinks', node });
  }

  /**
   * Claims a link from its URL fragment — `location.hash.slice(1)`, verbatim.
   * The fragment is the whole bearer capability, so clear it from the address
   * bar (`history.replaceState`) before awaiting this: a hash survives in
   * session-restore state and in the back/forward entry.
   */
  claimInviteLink(fragment: string): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'claimInviteLink', fragment });
  }

  /** Converts the claims waiting on the link minted at `node` into grants. */
  convertInviteClaims(node: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'convertInviteClaims', node });
  }

  acceptShare(sealedSharePointer: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'acceptShare', sealedSharePointer });
  }

  rotateNow(node: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'rotateNow', node });
  }

  /**
   * Saves the member's placement, provider and retention choice. A BYO bearer is
   * moved to the engine, not copied, so the caller's buffer is detached — and a
   * spent one cannot be re-sent: a retry re-reads its source, as `start` does.
   *
   * A bearer that is not a transferable buffer is refused here rather than sent,
   * because the worker hard-rejects it after every hop has already cloned it
   * (AGENTS.md 8): the copy it would leave behind is a live credential.
   */
  saveVaultSettings(settings: VaultSettingsDescriptor): Promise<CommandOutcomeDescriptor> {
    const token = settings.byo?.accessToken;
    if (token != null && !isBuffer(token)) {
      wipeBytes(token);
      return Promise.reject(new Error('accessToken must be a transferable buffer'));
    }
    return this.command({ kind: 'saveVaultSettings', settings });
  }

  /** Issues the single-use nonce an EIP-4361 message must embed. */
  siweChallenge(): Promise<string> {
    return this.transport.siweChallenge();
  }

  siweLogin(message: string, signature: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'siweLogin', message, signature });
  }

  private command(descriptor: CommandDescriptor): Promise<CommandOutcomeDescriptor> {
    return this.transport.command(descriptor);
  }
}
