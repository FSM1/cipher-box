/**
 * What the engine confirmed about sharing this session: the contacts it
 * verified at import, and the grants it accepted, per scope.
 *
 * Every entry is an outcome an engine command resolved with — an import
 * resolving *is* the proof its binding verified (blueprint/engine.md "Contact
 * import"), and a grant row exists only where a grant command returned. The
 * engine holds both lists durably but the facade exposes a read for neither, so
 * this stands in until it does; a host must not read absence from it.
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

/** Replaces the entry `matches` picks out, or appends when nothing matches. */
function upsert<T>(list: readonly T[], matches: (item: T) => boolean, next: T): T[] {
  return list.some(matches) ? list.map((item) => (matches(item) ? next : item)) : [...list, next];
}

/** Rewrites one scope's rows, leaving every other scope's array untouched. */
function withScope(scope: string, rows: readonly GrantRow[]): void {
  const grants = new Map(state.grants);
  if (rows.length === 0) grants.delete(scope);
  else grants.set(scope, Object.freeze(rows));
  publish(frozen(state.contacts, grants));
}

function recordGrant(scope: Uint8Array, contact: VerifiedContact, permission: Permission): void {
  const key = toHex(scope);
  const rows = state.grants.get(key) ?? EMPTY;
  withScope(
    key,
    upsert(rows, (row) => row.contact.key === contact.key, { contact, permission })
  );
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
    });
    publish(
      frozen(
        upsert(state.contacts, (held) => held.key === contact.key, contact),
        state.grants
      )
    );
    return contact;
  },

  /** Records an accepted grant, or the new permission on a standing row. */
  granted: recordGrant,

  /**
   * Records an accepted downgrade as what it is — the standing row's permission
   * changing to read. A recipient with no row on this scope records nothing: a
   * downgrade never introduces a grant.
   */
  downgraded(scope: Uint8Array, contact: VerifiedContact): void {
    const rows = state.grants.get(toHex(scope)) ?? EMPTY;
    if (rows.some((row) => row.contact.key === contact.key)) recordGrant(scope, contact, 'read');
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

/**
 * The rows this session recorded on the scope with this hex node id. Hex
 * because that is how the UI already addresses a node (`lib/nodeId.ts`), so a
 * render costs no re-encode. An empty result is "nothing recorded here", never
 * "nothing is granted here".
 */
export function grantsFor(current: SharingState, scopeKey: string): readonly GrantRow[] {
  return current.grants.get(scopeKey) ?? EMPTY;
}
