/**
 * The sharing surface for one scope: one facade command per user action, each
 * followed by a re-read of the engine's own sharing state
 * (`stores/sharing.store.ts`). The store mirrors nothing a command returned, so
 * a grant another device issued shows up and a row this session issued survives
 * a reload.
 */

import { useCallback, useMemo } from 'react';
import { toHex } from '@cipherbox/client';
import type { EngineFacade, Permission, SharingDescriptor } from '@cipherbox/client';
import { sharingStore, type VerifiedContact } from '../stores/sharing.store';
import { useCommandRunner } from './useCommandRunner';

/** Which call is in flight, or `null` when the sharing surface is idle. */
export type SharingCommand =
  | 'read'
  | 'importContact'
  | 'grant'
  | 'revoke'
  | 'changePermission'
  | 'renameGrantee'
  | 'createInviteLink'
  | 'revokeInviteLink'
  | 'convertInviteClaims';

export interface RevokeLinkOptions {
  /** Also cut the people who joined through the link (ADR 0025 D1). */
  removeGrantees: boolean;
}

export interface SharingActions {
  busy: SharingCommand | null;
  /** The last refusal, in the engine's own words; cleared by the next dispatch. */
  error: string | null;
  clearError(): void;
  /**
   * Reads this scope into the store and, where it carries a link, converts the
   * claims that wait on it (ADR 0023 D4).
   */
  open(): Promise<boolean>;
  /** Resolves `true` once the engine verified the code and re-read the book. */
  importContact(contactCode: Uint8Array): Promise<boolean>;
  grant(contact: VerifiedContact, permission: Permission): Promise<boolean>;
  revoke(contact: VerifiedContact): Promise<boolean>;
  changePermission(contact: VerifiedContact, permission: Permission): Promise<boolean>;
  renameGrantee(contact: VerifiedContact, name: string): Promise<boolean>;
  /**
   * Mints a link over this scope, resolving with the engine's fragment
   * (`MintedInviteLink`) or `null` where the engine refused. The fragment is
   * the link's whole capability and the engine hands it over once, so a caller
   * that drops it cannot ask for it again.
   */
  createInviteLink(
    permission: Permission,
    expiresAt: bigint,
    ownerName: string
  ): Promise<string | null>;
  /** Cuts the link `linkTag` names at this scope: its future claims end. */
  revokeInviteLink(linkTag: Uint8Array, options: RevokeLinkOptions): Promise<boolean>;
}

/**
 * The engine's fingerprint of each grantee key, by hex key. A row whose key is
 * not a curve point (an unattested row) has none, and neither does one whose
 * read failed: the row still renders, only without it.
 */
async function fingerprintsOf(
  facade: EngineFacade,
  view: SharingDescriptor
): Promise<Map<string, string>> {
  const entries = await Promise.all(
    (view.state?.grants ?? []).map((grant) =>
      facade.identityFingerprint(grant.recipientIdentityPublicKey).then(
        (fingerprint): [string, string] => [toHex(grant.recipientIdentityPublicKey), fingerprint],
        () => null
      )
    )
  );
  return new Map(entries.filter((entry) => entry !== null));
}

export function useSharingActions(scope: Uint8Array): SharingActions {
  const { busy, error, run, clearError } = useCommandRunner<SharingCommand>();
  // Keyed by the scope's hex id: a caller rebuilding the byte array each render
  // is the same scope, and re-reading on it would loop through the store the
  // read publishes to.
  const scopeKey = toHex(scope);
  const target = useMemo(() => scope, [scopeKey]);

  const read = useCallback(
    async (facade: EngineFacade) => {
      const view = await facade.sharing(target);
      sharingStore.reported(view, await fingerprintsOf(facade, view));
      return view;
    },
    [target]
  );

  return {
    busy,
    error,
    clearError,
    open: useCallback(async () => {
      let linked = false;
      const reached = await run('read', async (facade) => {
        linked = ((await read(facade)).state?.inviteLinks.length ?? 0) > 0;
      });
      if (!reached || !linked) return reached;
      return run('convertInviteClaims', async (facade) => {
        await facade.convertInviteClaims(target);
        await read(facade);
      });
    }, [run, read, target]),
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
    changePermission: useCallback(
      (contact, permission) =>
        run('changePermission', async (facade) => {
          await facade.changePermission(target, contact.identityPublicKey, permission);
          await read(facade);
        }),
      [run, read, target]
    ),
    renameGrantee: useCallback(
      (contact, name) =>
        run('renameGrantee', async (facade) => {
          await facade.renameGrantee(target, contact.identityPublicKey, name);
          await read(facade);
        }),
      [run, read, target]
    ),
    createInviteLink: useCallback(
      async (permission, expiresAt, ownerName) => {
        let fragment: string | null = null;
        await run('createInviteLink', async (facade) => {
          fragment = (await facade.createInviteLink(target, permission, expiresAt, ownerName))
            .fragment;
          await read(facade);
        });
        return fragment;
      },
      [run, read, target]
    ),
    revokeInviteLink: useCallback(
      (linkTag, _options) =>
        run('revokeInviteLink', async (facade) => {
          // The client takes no `removeGrantees` yet, so the options stop here.
          await facade.revokeInviteLink(target, linkTag);
          await read(facade);
        }),
      [run, read, target]
    ),
  };
}
