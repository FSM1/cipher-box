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

import { type AccountStoreNaming, eraseAccountStores } from './accountStores.js';
import { isBuffer, wipeBytes } from './buffers.js';
import type { EngineEventListener, EngineTransport } from './transport.js';
import { KEEP_STORED_BEARER, MAX_FRAGMENT_CHARS } from './worker/protocol.js';
import type {
  ApprovalDecision,
  CommandDescriptor,
  CommandOutcomeDescriptor,
  ForgottenResidual,
  NodeKind,
  OpenedStream,
  Permission,
  ReadDescriptor,
  ReadResult,
  StreamHandle,
  VaultSettingsDescriptor,
  WriteHandle,
  WriteTarget,
} from './worker/protocol.js';

/** The verified contact an import produced, with its two public keys. */
export type ImportedContact = Extract<CommandOutcomeDescriptor, { kind: 'contactImported' }>;

/** The bearer capability a mint produced — opaque characters for a URL fragment. */
export type MintedInviteLink = Extract<CommandOutcomeDescriptor, { kind: 'inviteLinkMinted' }>;

export class EngineFacade {
  // The account a forget erased, latched while the engine still names one, so
  // the teardown that clears the session cannot take the name with it.
  private forgotten: string | null = null;

  /**
   * `naming` must be the spelling the worker opened the stores under: the erase
   * names its containers rather than enumerating them, so a prefix it does not
   * share is a prefix it cannot take.
   */
  constructor(
    private readonly transport: EngineTransport,
    private readonly naming: AccountStoreNaming = {}
  ) {}

  /**
   * Cold start: hands the login secret to the engine once, transferred (the
   * caller's `secret` buffer is detached by the transfer). `accountId` names
   * whose durable state the engine opens. Resolves when the engine has run its
   * cold-start sequence (vault-pointer resolve, floor cold-seed, root adoption,
   * first snapshot event). `identityToken` is the token of the exchange this
   * start follows, which the engine's login presents (ADR 0058 D2); a restored
   * session passes none.
   */
  start(secret: ArrayBuffer, accountId: string, identityToken?: string): Promise<void> {
    return this.transport.start(secret, accountId, identityToken);
  }

  /**
   * Logout: the engine zeroizes its WASM state, then the worker is torn down.
   * Durable seams (floors, op queue, staged bytes, ciphertext cache) survive by
   * design — unless a {@link forgetDevice} preceded this, whose containers this
   * teardown is what finally lets go.
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
    await this.eraseForgottenStores();
  }

  /**
   * Forget this device: the engine ends the session and erases every durable
   * seam — the floors, op queue, staged bytes and ciphertext cache a logout
   * keeps (blueprint/web-client.md "Logout").
   *
   * Leaves the worker standing, so the {@link logout} that follows is still
   * what zeroizes it — and what removes the emptied containers. A refused erase
   * rejects rather than resolving.
   *
   * Answers with the {@link ForgottenResidual} the settling pass ahead of the
   * erase left behind.
   */
  async forgetDevice(): Promise<ForgottenResidual> {
    const outcome = await this.command({ kind: 'forgetDevice' });
    this.forgotten = this.transport.signedInAccount?.() ?? null;
    return outcome.kind === 'forgotten'
      ? {
          unsettledBytes: outcome.unsettledBytes,
          unsettledIsPartial: outcome.unsettledIsPartial,
          stalls: outcome.stalls,
        }
      : { unsettledBytes: null, unsettledIsPartial: false, stalls: 0n };
  }

  /**
   * Removes the containers a forgotten account named, so no name on the profile
   * still carries its public key ({@link eraseAccountStores}). Runs only after
   * teardown: an IndexedDB delete blocks while the engine holds a connection.
   */
  private async eraseForgottenStores(): Promise<void> {
    const account = this.forgotten;
    if (account === null) return;
    this.forgotten = null;
    await eraseAccountStores(account, this.naming);
  }

  /** Subscribes to the one-way engine event stream; returns an unsubscribe. */
  subscribe(listener: EngineEventListener): () => void {
    return this.transport.subscribe(listener);
  }

  /**
   * Serves one read and resolves with what that kind answers. A snapshot or a
   * sharing read of `null` reads the vault root. An invite fragment is the
   * whole bearer capability, as for [`claimInviteLink`], so an oversize one is
   * refused here, before a structured clone copies it into another realm.
   */
  read<D extends ReadDescriptor>(read: D): Promise<ReadResult<D>> {
    if (read.kind === 'invitePreview' && read.fragment.length > MAX_FRAGMENT_CHARS) {
      return Promise.reject(new Error('that is not an invite link'));
    }
    return this.transport.read(read);
  }

  /**
   * Opens a read stream over one file node, pinned to the head content version
   * for the handle's life. Released with `closeStream`.
   */
  openContentStream(node: Uint8Array): Promise<OpenedStream> {
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

  /**
   * Puts a soft-deleted node back, into `into` or the folder its bin entry
   * names for `null`. Rejects with `restoreTargetGone` when the vault no longer
   * holds that destination, with `restoreCrossesScope` when it lies in another
   * scope than the entry's, and with `notBinned` when the bin holds no entry.
   */
  restore(node: Uint8Array, into: Uint8Array | null): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'restore', node, into });
  }

  /**
   * Destroys a soft-deleted node and its bin entry, irreversibly. Rejects with
   * `notBinned` when the bin holds no entry for the node.
   */
  purge(node: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'purge', node });
  }

  rename(node: Uint8Array, newName: string): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'rename', node, newName });
  }

  relink(node: Uint8Array, newParent: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'relink', node, newParent });
  }

  /**
   * Puts one prior version back at the head of a file's history. It publishes a
   * new version rather than rewinding history, and moves no byte.
   */
  restoreVersion(node: Uint8Array, contentCid: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'restoreVersion', node, contentCid });
  }

  /** Drops one prior version of a file and reclaims its bytes. Irreversible. */
  deleteVersion(node: Uint8Array, contentCid: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'deleteVersion', node, contentCid });
  }

  /**
   * Cancel a queued upload by the op id `commitWrite` resolved with. Rejects
   * with `notAnUpload` when the op carries no content, and with
   * `tooLateToCancel` once the version's record is publishing.
   */
  cancelUpload(opId: bigint): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'cancelUpload', opId });
  }

  /**
   * Drops one parked write and releases its staged version. Irreversible, and
   * refused with `unknownDeadLetter` when this device holds no such write.
   */
  discardDeadLetter(opId: bigint): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'discardDeadLetter', opId });
  }

  /**
   * Re-queues one parked write's staged version as a fresh op anchored on the
   * head this device renders now, resolving `queued` with the new op id.
   */
  recoverDeadLetter(opId: bigint): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'recoverDeadLetter', opId });
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

  /** `granteeName` is the name the owner gives the grantee on the row. */
  grant(
    node: Uint8Array,
    recipientIdentityPublicKey: Uint8Array,
    permission: Permission,
    granteeName?: string
  ): Promise<CommandOutcomeDescriptor> {
    return this.command({
      kind: 'grant',
      node,
      recipientIdentityPublicKey,
      permission,
      granteeName: granteeName ?? null,
    });
  }

  revoke(
    node: Uint8Array,
    recipientIdentityPublicKey: Uint8Array
  ): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'revoke', node, recipientIdentityPublicKey });
  }

  changePermission(
    node: Uint8Array,
    recipientIdentityPublicKey: Uint8Array,
    permission: Permission
  ): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'changePermission', node, recipientIdentityPublicKey, permission });
  }

  renameGrantee(
    node: Uint8Array,
    recipientIdentityPublicKey: Uint8Array,
    name: string
  ): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'renameGrantee', node, recipientIdentityPublicKey, name });
  }

  /**
   * Mints an invite link; an `undefined` `expiresAt` takes the engine's default
   * lifetime, and an `undefined` `admissionCap` its default cap. `ownerName` is
   * what the fragment shows the holder, signed by the owner.
   */
  async createInviteLink(
    node: Uint8Array,
    permission: Permission,
    expiresAt?: bigint,
    // ADR 0027 D5 puts the owner name in the fragment but names no source for
    // it. The ADR 0027 D1 never-email rule applies by analogy, so it is empty.
    ownerName = '',
    admissionCap?: number
  ): Promise<MintedInviteLink> {
    const outcome = await this.command({
      kind: 'createInviteLink',
      node,
      permission,
      expiresAt: expiresAt ?? null,
      ownerName,
      admissionCap: admissionCap === undefined ? null : BigInt(admissionCap),
    });
    if (outcome.kind !== 'inviteLinkMinted') {
      throw new Error(`create invite link answered ${outcome.kind}`);
    }
    return outcome;
  }

  /**
   * Revokes the link `linkTag` names at `node` (its `SharingInviteLinkDescriptor.tag`):
   * every link holder loses access at once. With no tag it cuts the scope's only
   * link, which the engine refuses where the scope carries more. The people who
   * joined through the link keep access unless `removeGrantees` is set.
   */
  revokeInviteLink(
    node: Uint8Array,
    linkTag?: Uint8Array,
    removeGrantees = false
  ): Promise<CommandOutcomeDescriptor> {
    return this.command({
      kind: 'revokeInviteLink',
      node,
      linkTag: linkTag ?? null,
      removeGrantees,
    });
  }

  /**
   * Claims a link from its URL fragment — `location.hash.slice(1)`, verbatim.
   * The fragment is the whole bearer capability, so clear it from the address
   * bar (`history.replaceState`) before awaiting this: a hash survives in
   * session-restore state and in the back/forward entry. `name` is the name
   * the owner sees for the claimant: the sign-in display name, else empty,
   * never the email.
   */
  claimInviteLink(fragment: string, name: string): Promise<CommandOutcomeDescriptor> {
    // Refused here rather than sent: past this call the fragment is cloned into
    // the worker's realm — and, behind a follower, the leader tab's — before
    // anything measures it (AGENTS.md 8).
    if (fragment.length > MAX_FRAGMENT_CHARS) {
      return Promise.reject(new Error('that is not an invite link'));
    }
    return this.command({ kind: 'claimInviteLink', fragment, name });
  }

  /** Converts the claims waiting on the link minted at `node` into grants. */
  convertInviteClaims(node: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'convertInviteClaims', node });
  }

  /** Drops the claims the link minted at `node` refused at a cap. */
  dismissRefusedClaims(node: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'dismissRefusedClaims', node });
  }

  rotateNow(node: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'rotateNow', node });
  }

  /** Cuts the write keys of the scope root at `node` now, from any owner device. */
  rotateWriteNow(node: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'rotateWriteNow', node });
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
    if (token != null && token !== KEEP_STORED_BEARER && !isBuffer(token)) {
      wipeBytes(token);
      return Promise.reject(new Error('accessToken must be a transferable buffer'));
    }
    return this.command({ kind: 'saveVaultSettings', settings });
  }

  /** Links a signed EIP-4361 message to the account this session already holds. */
  siweLink(message: string, signature: Uint8Array): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'siweLink', message, signature });
  }

  /** Asks the API to email a link code to `email` for the account this session holds. */
  emailLinkSendCode(email: string): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'emailLinkSendCode', email });
  }

  /** Links the address `code` was sent to. The engine re-proves the account identity key. */
  emailLink(email: string, code: string): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'emailLink', email, code });
  }

  /** Unlinks one login method. The engine re-proves the account identity key. */
  unlinkAuthMethod(methodId: string): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'unlinkAuthMethod', methodId });
  }

  /** Registers this device's identity key on the account; `label` is optional. */
  registerDevice(
    publicKey: string,
    signature: string,
    identityToken: string,
    label: string | null
  ): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'registerDevice', publicKey, signature, identityToken, label });
  }

  /** Revokes one registered device key. */
  revokeDevice(deviceId: string): Promise<CommandOutcomeDescriptor> {
    return this.command({ kind: 'revokeDevice', deviceId });
  }

  /** Answers one rendezvous. A denial carries no sealed factor. */
  respondToApproval(
    requestId: string,
    decision: ApprovalDecision,
    devicePublicKey: string,
    ephemeralPublicKey: string,
    signature: string,
    sealedFactor: string | null
  ): Promise<CommandOutcomeDescriptor> {
    return this.command({
      kind: 'respondToApproval',
      requestId,
      decision,
      devicePublicKey,
      ephemeralPublicKey,
      signature,
      sealedFactor,
    });
  }

  private command(descriptor: CommandDescriptor): Promise<CommandOutcomeDescriptor> {
    return this.transport.command(descriptor);
  }
}
