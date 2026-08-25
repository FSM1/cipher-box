/**
 * The sharing surface for one scope: one facade command per user action, each
 * followed by a re-read of the engine's own sharing state
 * (`stores/sharing.store.ts`). The store mirrors nothing a command returned, so
 * a grant another device issued shows up and a row this session issued survives
 * a reload.
 */

import { useCallback, useMemo } from 'react';
import { toHex } from '@cipherbox/client';
import type { EngineFacade, Permission } from '@cipherbox/client';
import { sharingStore, type VerifiedContact } from '../stores/sharing.store';
import { useCommandRunner } from './useCommandRunner';

/** Which call is in flight, or `null` when the sharing surface is idle. */
export type SharingCommand =
  | 'read'
  | 'importContact'
  | 'grant'
  | 'revoke'
  | 'downgrade'
  | 'createInviteLink'
  | 'revokeInviteLink'
  | 'pruneInviteLinks'
  | 'convertInviteClaims';

export interface SharingActions {
  busy: SharingCommand | null;
  /** The last refusal, in the engine's own words; cleared by the next dispatch. */
  error: string | null;
  clearError(): void;
  /** Re-reads this scope's contacts and grants into the store. */
  reload(): Promise<boolean>;
  /** Resolves `true` once the engine verified the code and re-read the book. */
  importContact(contactCode: Uint8Array): Promise<boolean>;
  grant(contact: VerifiedContact, permission: Permission): Promise<boolean>;
  revoke(contact: VerifiedContact): Promise<boolean>;
  downgrade(contact: VerifiedContact): Promise<boolean>;
  /**
   * Mints a link over this scope, resolving with the engine's fragment
   * (`MintedInviteLink`) or `null` where the engine refused. An omitted
   * `expiresAt` mints one that never expires. The fragment is the link's whole
   * capability and the engine hands it over once, so a caller that drops it
   * cannot ask for it again.
   */
  createInviteLink(permission: Permission, expiresAt?: bigint): Promise<string | null>;
  /** Cuts this scope's live link: its future claims end, converted grants stand. */
  revokeInviteLink(): Promise<boolean>;
  /** Drops the records this scope's own commitment no longer carries. */
  pruneInviteLinks(): Promise<boolean>;
  /** Converts the claims waiting on this scope's link into grants. */
  convertInviteClaims(): Promise<boolean>;
}

export function useSharingActions(scope: Uint8Array): SharingActions {
  const { busy, error, run, clearError } = useCommandRunner<SharingCommand>();
  // Keyed by the scope's hex id: a caller rebuilding the byte array each render
  // is the same scope, and re-reading on it would loop through the store the
  // read publishes to.
  const scopeKey = toHex(scope);
  const target = useMemo(() => scope, [scopeKey]);

  const read = useCallback(
    async (facade: EngineFacade) => sharingStore.reported(await facade.sharing(target)),
    [target]
  );

  return {
    busy,
    error,
    clearError,
    reload: useCallback(() => run('read', read), [run, read]),
    importContact: useCallback(
      (contactCode) =>
        run('importContact', async (facade) => {
          await facade.importContact(contactCode);
          await read(facade);
        }),
      [run, read]
    ),
    grant: useCallback(
      (contact, permission) =>
        run('grant', async (facade) => {
          await facade.grant(target, contact.identityPublicKey, permission);
          await read(facade);
        }),
      [run, read, target]
    ),
    revoke: useCallback(
      (contact) =>
        run('revoke', async (facade) => {
          await facade.revoke(target, contact.identityPublicKey);
          await read(facade);
        }),
      [run, read, target]
    ),
    downgrade: useCallback(
      (contact) =>
        run('downgrade', async (facade) => {
          await facade.downgrade(target, contact.identityPublicKey);
          await read(facade);
        }),
      [run, read, target]
    ),
    createInviteLink: useCallback(
      async (permission, expiresAt) => {
        let fragment: string | null = null;
        await run('createInviteLink', async (facade) => {
          fragment = (await facade.createInviteLink(target, permission, expiresAt)).fragment;
          await read(facade);
        });
        return fragment;
      },
      [run, read, target]
    ),
    revokeInviteLink: useCallback(
      () =>
        run('revokeInviteLink', async (facade) => {
          await facade.revokeInviteLink(target);
          await read(facade);
        }),
      [run, read, target]
    ),
    pruneInviteLinks: useCallback(
      () =>
        run('pruneInviteLinks', async (facade) => {
          await facade.pruneInviteLinks(target);
          await read(facade);
        }),
      [run, read, target]
    ),
    convertInviteClaims: useCallback(
      () =>
        run('convertInviteClaims', async (facade) => {
          await facade.convertInviteClaims(target);
          await read(facade);
        }),
      [run, read, target]
    ),
  };
}
