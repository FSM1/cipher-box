/**
 * The sharing state the engine reported, per scope: this vault's verified
 * contact book, and the grants a scope's own record commits.
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
  /** A further share here would be accepted, so a mint is worth offering. */
  readonly canMintShare: boolean;
  /** `null` where the engine reached the scope but not the owner's link records. */
  readonly inviteLinks: SharingInviteLinksDescriptor | null;
}

export interface SharingState {
  readonly contacts: readonly VerifiedContact[];
  /** Each scope's own state, keyed by the scope root's hex node id. */
  readonly scopes: ReadonlyMap<string, ScopeSharing>;
}

let state: SharingState = frozen([], new Map());
const listeners = new Set<() => void>();

function frozen(
  contacts: readonly VerifiedContact[],
  scopes: ReadonlyMap<string, ScopeSharing>
): SharingState {
  return Object.freeze({ contacts: Object.freeze(contacts), scopes });
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
   * nobody". One resolve settles the scope, so an unreachable read withholds the
   * mint verdict with the grants.
   */
  reported(view: SharingDescriptor): void {
    const scopes = new Map(state.scopes);
    if (view.grants !== null) {
      scopes.set(
        toHex(view.scope),
        Object.freeze({
          grants: Object.freeze(
            view.grants.map((grant) =>
              Object.freeze({
                contact: contactOf(grant.recipientIdentityPublicKey),
                permission: grant.permission,
              })
            )
          ),
          canMintShare: view.canMintShare,
          inviteLinks: view.inviteLinks === null ? null : Object.freeze(view.inviteLinks),
        })
      );
    }
    publish(
      frozen(
        view.contacts.map((contact) => contactOf(contact.identityPublicKey)),
        scopes
      )
    );
  },

  clear(): void {
    if (state.contacts.length === 0 && state.scopes.size === 0) return;
    publish(frozen([], new Map()));
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

/** An empty array is the engine's own answer that the scope commits no grant. */
export function grantsFor(current: SharingState, scopeKey: string): readonly GrantRow[] | null {
  return sharingFor(current, scopeKey)?.grants ?? null;
}
