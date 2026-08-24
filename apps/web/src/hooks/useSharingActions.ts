/**
 * The sharing write path: one facade command per user action, and a store entry
 * only where the engine answered. A refused command records nothing, so the
 * rendered contact and grant lists are exactly what the engine confirmed
 * (blueprint/web-client.md "Sharing UI is facade commands end to end").
 */

import { useCallback, useState } from 'react';
import type { EngineFacade, Permission } from '@cipherbox/client';
import { errorMessage } from '../lib/errorMessage';
import { useEngine } from '../providers/EngineProvider';
import { sharingStore, type VerifiedContact } from '../sharing/sharingStore';

/** Which command is in flight, or `null` when the sharing surface is idle. */
export type SharingCommand = 'importContact' | 'grant' | 'revoke' | 'downgrade';

/**
 * The last refusal, named by the command that drew it. The import step and the
 * grant list share one dispatcher and each shows only its own failure — a
 * refused import must not surface as a verdict on a grant.
 */
export interface SharingFailure {
  command: SharingCommand;
  message: string;
}

export interface SharingActions {
  busy: SharingCommand | null;
  failure: SharingFailure | null;
  /** Resolves `true` once the engine verified the code and returned a contact. */
  importContact(contactCode: Uint8Array): Promise<boolean>;
  grant(scope: Uint8Array, contact: VerifiedContact, permission: Permission): Promise<boolean>;
  revoke(scope: Uint8Array, contact: VerifiedContact): Promise<boolean>;
  downgrade(scope: Uint8Array, contact: VerifiedContact): Promise<boolean>;
}

export function useSharingActions(): SharingActions {
  const client = useEngine();
  const [busy, setBusy] = useState<SharingCommand | null>(null);
  const [failure, setFailure] = useState<SharingFailure | null>(null);

  const run = useCallback(
    async (
      command: SharingCommand,
      dispatch: (facade: EngineFacade) => Promise<void>
    ): Promise<boolean> => {
      if (client === null) {
        setFailure({ command, message: 'the engine is not ready yet' });
        return false;
      }
      setBusy(command);
      setFailure(null);
      try {
        await dispatch(client.facade);
        return true;
      } catch (refusal: unknown) {
        setFailure({ command, message: errorMessage(refusal) });
        return false;
      } finally {
        setBusy(null);
      }
    },
    [client]
  );

  return {
    busy,
    failure,
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
