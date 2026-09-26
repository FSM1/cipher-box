import { Fragment, useState } from 'react';
import { toHex } from '@cipherbox/client';
import type { Permission, SharingInviteLinkDescriptor } from '@cipherbox/client';
import type { SharingActions } from '../../hooks/useSharingActions';
import { accessLabel, linkLabel } from '../../sharing/inviteLink';
import type { GrantRow, ScopeSharing } from '../../stores/sharing.store';
import { plural } from '../../vault/selection';
import { Confirm } from './Confirm';

/** Who a row names: the name on it, else its fingerprint. */
export function granteeLabel(grant: GrantRow): string {
  return grant.name?.name ?? grant.fingerprint ?? 'an unnamed person';
}

/**
 * The owner and each grantee, then the live links: a link holder reads the
 * folder before a conversion lists them as a grantee (ADR 0024).
 */
export function peopleCount(scope: ScopeSharing): string {
  const live = plural(scope.inviteLinks.filter((link) => !link.expired).length, 'live link');
  const people = String(scope.grants.length + 1);
  return live === null ? people : `${people} · ${live}`;
}

interface PeopleTableProps {
  /** `null` where no read reached the scope root. */
  grants: readonly GrantRow[] | null;
  links: readonly SharingInviteLinkDescriptor[];
  actions: SharingActions;
  busy: boolean;
}

/**
 * Everyone with access to the folder, the owner first. Each grantee row edits
 * its name and its permission in place and revokes behind a confirmation that
 * shows the fingerprint, since the name is only a label (ADR 0027 D7).
 */
export function PeopleTable({ grants, links, actions, busy }: PeopleTableProps) {
  const [renaming, setRenaming] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);

  if (grants === null) {
    return (
      <p className="sharing-note" data-testid="share-grants-unavailable">
        {'// people unavailable — no read reached this folder'}
      </p>
    );
  }

  return (
    <table className="sharing-people" data-testid="share-people">
      <thead>
        <tr>
          <th>who</th>
          <th>got in</th>
          <th>can</th>
          <th aria-label="actions" />
        </tr>
      </thead>
      <tbody>
        <tr className="sharing-people-owner" data-testid="share-owner-row">
          <td>you</td>
          <td>owner</td>
          <td>
            <span className="details-badge">owner</span>
          </td>
          <td />
        </tr>
        {grants.map((grant) => {
          const who = granteeLabel(grant);
          const key = grant.contact.key;
          return (
            <Fragment key={key}>
              <tr data-testid="share-grant-row">
                <td title={grant.fingerprint ?? undefined} data-testid="share-grantee">
                  {renaming === key ? (
                    <RenameField
                      initial={grant.name?.name ?? ''}
                      busy={busy}
                      onCancel={() => setRenaming(null)}
                      onSave={(name) =>
                        void actions.renameGrantee(grant.contact, name).then((renamed) => {
                          if (renamed) setRenaming(null);
                        })
                      }
                    />
                  ) : (
                    <button
                      type="button"
                      className="sharing-name"
                      onClick={() => setRenaming(key)}
                      disabled={busy}
                      aria-label={`rename ${who}`}
                      data-testid="share-rename"
                    >
                      {who}
                      {grant.name?.source === 'claimant' && (
                        <span className="sharing-suggested">suggested</span>
                      )}
                    </button>
                  )}
                </td>
                <td className="sharing-dim" data-testid="share-got-in">
                  {grant.viaLink === null ? 'direct' : 'via link'}
                </td>
                <td>
                  <select
                    className="dialog-input sharing-permission"
                    aria-label={`access for ${who}`}
                    value={grant.permission}
                    onChange={(event) =>
                      void actions.changePermission(grant.contact, event.target.value as Permission)
                    }
                    disabled={busy}
                    data-testid="share-grant-permission"
                  >
                    <option value="read">{accessLabel('read')}</option>
                    <option value="write">{accessLabel('write')}</option>
                  </select>
                </td>
                <td>
                  <button
                    type="button"
                    className="dialog-button dialog-button--danger"
                    onClick={() => setConfirming(key)}
                    disabled={busy}
                    data-testid="share-revoke"
                  >
                    revoke
                  </button>
                </td>
              </tr>
              {confirming === key && (
                <tr>
                  <td colSpan={4}>
                    <Confirm
                      title={`remove ${who}?`}
                      confirmLabel={actions.busy === 'revoke' ? 'revoking...' : 'revoke'}
                      busy={busy}
                      onKeep={() => setConfirming(null)}
                      onConfirm={() =>
                        void actions.revoke(grant.contact).then((revoked) => {
                          if (revoked) setConfirming(null);
                        })
                      }
                      testId="share-revoke"
                    >
                      <p className="sharing-note">
                        {`// fingerprint ${grant.fingerprint ?? 'unavailable'}`}
                      </p>
                      <p className="sharing-note">
                        {'// they lose access to this folder and everything in it'}
                      </p>
                    </Confirm>
                  </td>
                </tr>
              )}
            </Fragment>
          );
        })}
        {grants.length === 0 && (
          <tr>
            <td colSpan={4} className="sharing-people-empty" data-testid="share-no-grants">
              <NoGrantees links={links} />
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );
}

function NoGrantees({ links }: { links: readonly SharingInviteLinkDescriptor[] }) {
  const live = links.filter((link) => !link.expired);
  if (live.length === 0) {
    return <>{'// only you have access — create a link below to invite someone'}</>;
  }
  return (
    <>
      {'// no one has joined yet — whoever holds a live link can already open this folder'}
      {live
        .filter((link) => link.pendingClaims > 0)
        .map((link) => (
          <div key={toHex(link.tag)} data-testid="share-link-waiting">
            {`// ${plural(link.pendingClaims, 'claim')} waiting on the ${linkLabel(link)}`}
          </div>
        ))}
    </>
  );
}

function RenameField({
  initial,
  busy,
  onCancel,
  onSave,
}: {
  initial: string;
  busy: boolean;
  onCancel: () => void;
  onSave: (name: string) => void;
}) {
  const [name, setName] = useState(initial);
  const trimmed = name.trim();
  return (
    <form
      className="sharing-rename"
      onSubmit={(event) => {
        event.preventDefault();
        if (trimmed !== '') onSave(trimmed);
      }}
    >
      <input
        className="dialog-input"
        aria-label="name"
        value={name}
        onChange={(event) => setName(event.target.value)}
        disabled={busy}
        autoFocus
        data-testid="share-rename-input"
      />
      <button type="button" className="dialog-button" onClick={onCancel} disabled={busy}>
        cancel
      </button>
      <button
        type="submit"
        className="dialog-button"
        disabled={busy || trimmed === ''}
        data-testid="share-rename-save"
      >
        save
      </button>
    </form>
  );
}
