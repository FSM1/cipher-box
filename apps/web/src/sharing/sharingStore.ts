/**
 * What the engine confirmed about sharing this session: the contacts it
 * verified at import, and the grants it accepted, per scope.
 *
 * Every entry is an outcome an engine command resolved with — an import
 * resolving *is* the proof its binding verified (blueprint/engine.md "Contact
 * import"), and a grant row exists only where a grant/downgrade command
 * returned. Nothing here re-checks anything and nothing is inferred.
 *
 * Memory only, and cleared with the session that made it: these rows name an
 * identity's peers, so they must not outlive it.
 */

import { toHex } from '@cipherbox/client';
import type { ImportedContact, Permission } from '@cipherbox/client';

/** A contact the engine verified at import; `key` is its identity, as hex. */
export interface VerifiedContact {
  readonly key: string;
  readonly identityPublicKey: Uint8Array;
  readonly encPublicKey: Uint8Array;
}

/** One recipient's standing on one scope. */
export interface GrantRow {
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

/**
 * Rewrites one scope's rows, leaving every other scope's array reference-equal
 * so a change to one shared folder does not repaint the rest.
 */
function withScope(scope: string, rows: readonly GrantRow[]): void {
  const grants = new Map(state.grants);
  if (rows.length === 0) grants.delete(scope);
  else grants.set(scope, Object.freeze(rows));
  publish(frozen(state.contacts, grants));
}

export const sharingStore = {
  subscribe(onStoreChange: () => void): () => void {
    listeners.add(onStoreChange);
    return () => listeners.delete(onStoreChange);
  },
  getState: (): SharingState => state,

  /**
   * Records a verified contact. A re-import replaces the entry for that
   * identity rather than adding a second, matching the engine's contact book:
   * both codes carry that identity's own signature, so the later one is the
   * contact rotating their own subkey.
   */
  contactImported(outcome: ImportedContact): VerifiedContact {
    const contact: VerifiedContact = Object.freeze({
      key: toHex(outcome.identityPublicKey),
      identityPublicKey: outcome.identityPublicKey,
      encPublicKey: outcome.encPublicKey,
    });
    const contacts = state.contacts.some((held) => held.key === contact.key)
      ? state.contacts.map((held) => (held.key === contact.key ? contact : held))
      : [...state.contacts, contact];
    publish(frozen(contacts, state.grants));
    return contact;
  },

  /** Records an accepted grant, or the new permission on a standing row. */
  granted(scope: Uint8Array, contact: VerifiedContact, permission: Permission): void {
    const key = toHex(scope);
    const rows = state.grants.get(key) ?? EMPTY;
    withScope(
      key,
      rows.some((row) => row.contact.key === contact.key)
        ? rows.map((row) => (row.contact.key === contact.key ? { contact, permission } : row))
        : [...rows, { contact, permission }]
    );
  },

  /**
   * Records an accepted downgrade as what it is — the standing row's permission
   * changing to read, in place. A recipient with no row on this scope records
   * nothing: a downgrade never introduces a grant.
   */
  downgraded(scope: Uint8Array, contact: VerifiedContact): void {
    const key = toHex(scope);
    const rows = state.grants.get(key) ?? EMPTY;
    if (!rows.some((row) => row.contact.key === contact.key)) return;
    withScope(
      key,
      rows.map((row) =>
        row.contact.key === contact.key ? { contact: row.contact, permission: 'read' } : row
      )
    );
  },

  /** Records an accepted revoke: the recipient has no standing on this scope. */
  revoked(scope: Uint8Array, contact: VerifiedContact): void {
    const key = toHex(scope);
    const rows = state.grants.get(key) ?? EMPTY;
    const next = rows.filter((row) => row.contact.key !== contact.key);
    if (next.length !== rows.length) withScope(key, next);
  },

  clear(): void {
    if (state.contacts.length === 0 && state.grants.size === 0) return;
    publish(frozen([], new Map()));
  },
};

/** The rows standing on `scope`, or none before the first grant lands on it. */
export function grantsFor(current: SharingState, scope: Uint8Array | null): readonly GrantRow[] {
  return scope === null ? EMPTY : (current.grants.get(toHex(scope)) ?? EMPTY);
}
