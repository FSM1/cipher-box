/**
 * The sharing surface for one scope: one facade command per user action, each
 * followed by a re-read of the engine's own sharing state
 * (`stores/sharing.store.ts`). The store mirrors nothing a command returned, so
 * a grant another device issued shows up and a row this session issued survives
 * a reload.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { toHex } from '@cipherbox/client';
import type { EngineFacade, Permission, SharingDescriptor } from '@cipherbox/client';
import { errorMessage } from '../lib/errorMessage';
import { useEngine } from '../providers/EngineProvider';
import { sharingFor, sharingStore, type VerifiedContact } from '../stores/sharing.store';
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
  | 'convertInviteClaims'
  | 'dismissRefusedClaims';

/** How long the "joined" notice stays up. */
export const JOINED_NOTICE_MS = 8_000;

/** The engine's refusal of a conversion while another pass runs on this device. */
const CONVERSION_RUNNING = 'a-conversion-pass-is-running';

export interface RevokeLinkOptions {
  /** Also cut the people who joined through the link (ADR 0025 D1). */
  removeGrantees: boolean;
}

export interface SharingActions {
  busy: SharingCommand | null;
  /** The last refusal, in the engine's own words; cleared by the next dispatch. */
  error: string | null;
  clearError(): void;
  /** Who joined this scope through a link while the dialog was open, until the notice lapses. */
  joined: string | null;
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
    ownerName: string,
    admissionCap: number
  ): Promise<string | null>;
  /**
   * Cuts the link `linkTag` names at this scope: its future claims end. With
   * `removeGrantees`, the people who joined through it lose access too.
   */
  revokeInviteLink(linkTag: Uint8Array, options: RevokeLinkOptions): Promise<boolean>;
  /** Drops the claims this scope's links refused at a cap from this device's record. */
  dismissRefusedClaims(): Promise<boolean>;
}

/**
 * How a joiner reads in the notice. The name is the claimant's own suggestion,
 * so it never shows without the fingerprint prefix beside it.
 */
export function joinedLabel(name: string, fingerprint: string): string {
  const prefix = fingerprint.split(' ').slice(0, 2).join(' ');
  return name === '' ? prefix : `${name} (${prefix})`;
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

  // Only the latest read publishes: an event read that finishes after a
  // command's read holds older state.
  const readSeq = useRef(0);
  const read = useCallback(
    async (facade: EngineFacade) => {
      const seq = ++readSeq.current;
      const view = await facade.sharing(target);
      const fingerprints = await fingerprintsOf(facade, view);
      if (seq === readSeq.current) sharingStore.reported(view, fingerprints);
      return view;
    },
    [target]
  );

  const client = useEngine();
  const [joined, setJoined] = useState<string | null>(null);
  useEffect(() => {
    if (client === null) return;
    // One re-read at a time: a burst of events folds into one trailing read. A
    // sharing read emits no `snapshotUpdated`, so a re-read cannot loop.
    let reading = false;
    let again = false;
    const reread = () => {
      if (reading) {
        again = true;
        return;
      }
      reading = true;
      // A failed re-read leaves the last view drawn.
      void read(client.facade)
        .catch(() => undefined)
        .finally(() => {
          reading = false;
          if (again) {
            again = false;
            reread();
          }
        });
    };
    return client.facade.subscribe((event) => {
      // A conversion pass that moves only the claim counts reports them here,
      // and only a scope with a link has claim counts.
      if (event.kind === 'snapshotUpdated') {
        const links = sharingFor(sharingStore.getState(), scopeKey)?.inviteLinks.length ?? 0;
        if (links > 0) reread();
        return;
      }
      if (event.kind !== 'granteeJoined' || toHex(event.scopeRoot) !== scopeKey) return;
      setJoined(joinedLabel(event.name, event.fingerprint));
      reread();
    });
  }, [client, read, scopeKey]);
  useEffect(() => {
    if (joined === null) return;
    const lapse = setTimeout(() => setJoined(null), JOINED_NOTICE_MS);
    return () => clearTimeout(lapse);
  }, [joined]);

  return {
    busy,
    error,
    clearError,
    joined,
    open: useCallback(async () => {
      let linked = false;
      const reached = await run('read', async (facade) => {
        linked = ((await read(facade)).state?.inviteLinks.length ?? 0) > 0;
      });
      if (!reached || !linked) return reached;
      return run('convertInviteClaims', async (facade) => {
        try {
          await facade.convertInviteClaims(target);
        } catch (refusal: unknown) {
          // The running pass emits `granteeJoined` or `snapshotUpdated`, and each re-reads.
          if (errorMessage(refusal).endsWith(`: ${CONVERSION_RUNNING}`)) return;
          throw refusal;
        }
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
      async (permission, expiresAt, ownerName, admissionCap) => {
        let fragment: string | null = null;
        await run('createInviteLink', async (facade) => {
          fragment = (
            await facade.createInviteLink(target, permission, expiresAt, ownerName, admissionCap)
          ).fragment;
          await read(facade);
        });
        return fragment;
      },
      [run, read, target]
    ),
    revokeInviteLink: useCallback(
      (linkTag, options) =>
        run('revokeInviteLink', async (facade) => {
          await facade.revokeInviteLink(target, linkTag, options.removeGrantees);
          await read(facade);
        }),
      [run, read, target]
    ),
    dismissRefusedClaims: useCallback(
      () =>
        run('dismissRefusedClaims', async (facade) => {
          await facade.dismissRefusedClaims(target);
          await read(facade);
        }),
      [run, read, target]
    ),
  };
}
