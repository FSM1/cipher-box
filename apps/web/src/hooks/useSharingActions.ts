/**
 * The sharing write path: one facade command per user action, and a store entry
 * only where the engine answered (`stores/sharing.store.ts`).
 */

import { useCallback } from 'react';
import type { Permission } from '@cipherbox/client';
import { sharingStore, type VerifiedContact } from '../stores/sharing.store';
import { useCommandRunner } from './useCommandRunner';

/** Which command is in flight, or `null` when the sharing surface is idle. */
export type SharingCommand = 'importContact' | 'grant' | 'revoke' | 'downgrade';

export interface SharingActions {
  busy: SharingCommand | null;
  /** The last refusal, in the engine's own words; cleared by the next dispatch. */
  error: string | null;
  clearError(): void;
  /** Resolves `true` once the engine verified the code and returned a contact. */
  importContact(contactCode: Uint8Array): Promise<boolean>;
  grant(scope: Uint8Array, contact: VerifiedContact, permission: Permission): Promise<boolean>;
  revoke(scope: Uint8Array, contact: VerifiedContact): Promise<boolean>;
  downgrade(scope: Uint8Array, contact: VerifiedContact): Promise<boolean>;
}

export function useSharingActions(): SharingActions {
  const { busy, error, run, clearError } = useCommandRunner<SharingCommand>();

  return {
    busy,
    error,
    clearError,
    importContact: useCallback(
      (contactCode) =>
        run('importContact', async (facade) => {
          sharingStore.contactImported(await facade.importContact(contactCode));
        }),
      [run]
    ),
    grant: useCallback(
      (scope, contact, permission) =>
        run('grant', async (facade) => {
          await facade.grant(scope, contact.identityPublicKey, permission);
          sharingStore.granted(scope, contact, permission);
        }),
      [run]
    ),
    revoke: useCallback(
      (scope, contact) =>
        run('revoke', async (facade) => {
          await facade.revoke(scope, contact.identityPublicKey);
          sharingStore.revoked(scope, contact);
        }),
      [run]
    ),
    downgrade: useCallback(
      (scope, contact) =>
        run('downgrade', async (facade) => {
          await facade.downgrade(scope, contact.identityPublicKey);
          sharingStore.downgraded(scope, contact);
        }),
      [run]
    ),
  };
}
