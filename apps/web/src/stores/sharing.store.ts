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
import type { Permission, SharingDescriptor } from '@cipherbox/client';

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

export interface SharingState {
  readonly contacts: readonly VerifiedContact[];
  /** Grant rows by scope, keyed by the scope root's hex node id. */
  readonly grants: ReadonlyMap<string, readonly GrantRow[]>;
}

const EMPTY: readonly GrantRow[] = Object.freeze([]);

let state: SharingState = frozen([], new Map());
const listeners = new Set<() => void>();

function frozen(
  contacts: readonly VerifiedContact[],
  grants: ReadonlyMap<string, readonly GrantRow[]>
): SharingState {
  return Object.freeze({ contacts: Object.freeze(contacts), grants });
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
   * and the view's scope takes its rows. Every other scope keeps what its own
   * read left, since this view speaks for one scope only.
   */
  reported(view: SharingDescriptor): void {
    const grants = new Map(state.grants);
    grants.set(
      toHex(view.scope),
      Object.freeze(
        view.grants.map((grant) =>
          Object.freeze({
            contact: contactOf(grant.recipientIdentityPublicKey),
            permission: grant.permission,
          })
        )
      )
    );
    publish(
      frozen(
        view.contacts.map((contact) => contactOf(contact.identityPublicKey)),
        grants
      )
    );
  },

  clear(): void {
    if (state.contacts.length === 0 && state.grants.size === 0) return;
    publish(frozen([], new Map()));
  },
};

/**
 * The rows the engine last reported for the scope with this hex node id. Hex
 * because that is how the UI already addresses a node (`lib/nodeId.ts`), so a
 * render costs no re-encode. Empty until a read lands, and empty afterwards for
 * a scope whose record commits no grant.
 */
export function grantsFor(current: SharingState, scopeKey: string): readonly GrantRow[] {
  return current.grants.get(scopeKey) ?? EMPTY;
}
