/**
 * The sharing state the engine reported, per scope: this vault's verified
 * contact book, this member's own contact code, and the grants a scope's own
 * record commits.
 *
 * A projection of `facade.sharing` with no independent writers — a command
 * re-reads rather than patching a row here, so the store holds nothing the
 * engine did not report.
 *
 * Memory only, and cleared with the session that made it: these rows name an
 * identity's peers, so they must not outlive it.
 */

import { toHex } from '@cipherbox/client';
import type {
  Permission,
  SharingDescriptor,
  SharingInviteLinksDescriptor,
} from '@cipherbox/client';

/** A contact the engine re-verified from its stored code; `key` is its identity, as hex. */
export interface VerifiedContact {
  readonly key: string;
  readonly identityPublicKey: Uint8Array;
}

/** One recipient's standing on one scope, as that scope's ledger commits it. */
export interface GrantRow {
  /**
   * The recipient this row names. A row the owner could not vouch for carries
   * an all-zero identity key, which matches no imported contact.
   */
  readonly contact: VerifiedContact;
  readonly permission: Permission;
}

/** What one scope's own record says, as the engine last reported it. */
export interface ScopeSharing {
  readonly grants: readonly GrantRow[];
  /**
   * The refusal a contact grant here would report, or `null` where the engine
   * would accept one. Named by the engine, never derived here.
   */
  readonly grantRefusal: string | null;
  /** The refusal an invite-link mint here would report, or `null`. */
  readonly inviteLinkRefusal: string | null;
  /** `null` where the engine reached the scope but not the owner's link records. */
  readonly inviteLinks: SharingInviteLinksDescriptor | null;
}

export interface SharingState {
  readonly contacts: readonly VerifiedContact[];
  /**
   * This member's own contact code as hex, the encoding `sharing/contactCode`
   * parses a pasted one from — so an exchange round-trips. `null` until a read
   * has landed.
   */
  readonly ownContactCode: string | null;
  /** Each scope's own state, keyed by the scope root's hex node id. */
  readonly scopes: ReadonlyMap<string, ScopeSharing>;
}

let state: SharingState = frozen([], null, new Map());
const listeners = new Set<() => void>();

function frozen(
  contacts: readonly VerifiedContact[],
  ownContactCode: string | null,
  scopes: ReadonlyMap<string, ScopeSharing>
): SharingState {
  return Object.freeze({ contacts: Object.freeze(contacts), ownContactCode, scopes });
}

function publish(next: SharingState): void {
  state = next;
  for (const listener of listeners) listener();
}

function contactOf(identityPublicKey: Uint8Array): VerifiedContact {
  return Object.freeze({ key: toHex(identityPublicKey), identityPublicKey });
}

export const sharingStore = {
  subscribe(onStoreChange: () => void): () => void {
    listeners.add(onStoreChange);
    return () => listeners.delete(onStoreChange);
  },
  getState: (): SharingState => state,

  /**
   * Takes the view the engine reported: the contact book replaces the held one,
   * and the view's scope takes its state. Every other scope keeps what its own
   * read left, since this view speaks for one scope only.
   *
   * A view whose scope the engine could not reach leaves that scope as it stood
   * — last-known-good, never an empty list a render would read as "shared with
   * nobody".
   */
  reported(view: SharingDescriptor): void {
    const scopes = new Map(state.scopes);
    if (view.state !== null) {
      scopes.set(
        toHex(view.scope),
        Object.freeze({
          grants: Object.freeze(
            view.state.grants.map((grant) =>
              Object.freeze({
                contact: contactOf(grant.recipientIdentityPublicKey),
                permission: grant.permission,
              })
            )
          ),
          grantRefusal: view.state.grantRefusal,
          inviteLinkRefusal: view.state.inviteLinkRefusal,
          inviteLinks:
            view.state.inviteLinks === null ? null : Object.freeze(view.state.inviteLinks),
        })
      );
    }
    publish(
      frozen(
        view.contacts.map((contact) => contactOf(contact.identityPublicKey)),
        toHex(view.ownContactCode),
        scopes
      )
    );
  },

  clear(): void {
    if (state.contacts.length === 0 && state.ownContactCode === null && state.scopes.size === 0) {
      return;
    }
    publish(frozen([], null, new Map()));
  },
};

/**
 * What the engine last reported for the scope with this hex node id, or `null`
 * where no read has yet reached it. Hex because that is how the UI already
 * addresses a node (`lib/nodeId.ts`), so a render costs no re-encode.
 *
 * `null` is the absence of an answer, which a render must not spell as one.
 */
export function sharingFor(current: SharingState, scopeKey: string): ScopeSharing | null {
  return current.scopes.get(scopeKey) ?? null;
}
