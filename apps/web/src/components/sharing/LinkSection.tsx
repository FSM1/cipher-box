import { useRef, useState } from 'react';
import { toHex } from '@cipherbox/client';
import type { Permission, SharingInviteLinkDescriptor } from '@cipherbox/client';
import type { SharingActions } from '../../hooks/useSharingActions';
import {
  accessLabel,
  expiryAt,
  expiryLabel,
  inviteUrl,
  joinedThrough,
  LINK_LIFETIMES,
  linkLabel,
  type LinkLifetime,
} from '../../sharing/inviteLink';
import { storedOwnerName, storeOwnerName } from '../../sharing/ownerName';
import { refusalLabel } from '../../sharing/shareRefusals';
import type { ScopeSharing } from '../../stores/sharing.store';
import { plural } from '../../vault/selection';
import { CopyableValue } from '../file-browser/details/DetailsPrimitives';
import { granteeLabel } from './PeopleTable';

interface LinkSectionProps {
  scope: ScopeSharing;
  actions: SharingActions;
  busy: boolean;
  /** The link minted in this dialog, shown once; `null` until a mint lands. */
  fresh: string | null;
  onMinted: (url: string) => void;
}

/**
 * The link half of the share dialog: an inline row that mints a link, the
 * minted link shown once, and one chip per link the scope carries, each with
 * a revoke behind a confirmation (ADR 0023 D7, ADR 0025 D1).
 */
export function LinkSection({ scope, actions, busy, fresh, onMinted }: LinkSectionProps) {
  const [permission, setPermission] = useState<Permission>('read');
  const [lifetime, setLifetime] = useState<LinkLifetime>('7 days');
  const [ownerName, setOwnerName] = useState(storedOwnerName);
  const [confirming, setConfirming] = useState<string | null>(null);
  // Closed before the dispatch rather than by a render: two activations in one
  // frame would mint two links and strand the first, a live capability nothing
  // can name again — and `busy` is itself the render-late value that misses it.
  const minting = useRef(false);

  const mint = () => {
    if (busy || minting.current) return;
    minting.current = true;
    const name = ownerName.trim();
    storeOwnerName(name);
    void actions
      .createInviteLink(permission, expiryAt(lifetime, Date.now()), name)
      .then((fragment) => {
        if (fragment !== null) onMinted(inviteUrl(fragment));
      })
      .finally(() => {
        minting.current = false;
      });
  };

  const refused = scope.inviteLinkRefusal;
  const chosen = scope.inviteLinks.find((link) => tagKey(link) === confirming) ?? null;

  return (
    <div className="dialog-content" data-testid="share-links">
      <p className="dialog-label">invite with a link</p>
      {refused !== null ? (
        <p className="sharing-note" data-testid="share-no-mint" data-check={refused}>
          {`// ${refusalLabel(refused)}`}
        </p>
      ) : (
        <>
          <div className="sharing-inline">
            <select
              className="dialog-input"
              aria-label="link permission"
              value={permission}
              onChange={(event) => setPermission(event.target.value as Permission)}
              disabled={busy}
            >
              <option value="read">{`can ${accessLabel('read')}`}</option>
              <option value="write">{`can ${accessLabel('write')}`}</option>
            </select>
            <select
              className="dialog-input"
              aria-label="link expires"
              value={lifetime}
              onChange={(event) => setLifetime(event.target.value as LinkLifetime)}
              disabled={busy}
            >
              {Object.keys(LINK_LIFETIMES).map((option) => (
                <option key={option} value={option}>
                  {`expires in ${option}`}
                </option>
              ))}
            </select>
            <button
              type="button"
              className="dialog-button dialog-button--primary sharing-nowrap"
              onClick={mint}
              disabled={busy}
              data-testid="share-mint-link"
            >
              {actions.busy === 'createInviteLink' ? 'creating...' : 'create link'}
            </button>
          </div>
          <input
            className="dialog-input"
            aria-label="your name on the link"
            placeholder="your name on the link — optional, never your email"
            value={ownerName}
            onChange={(event) => setOwnerName(event.target.value)}
            disabled={busy}
            data-testid="share-owner-name"
          />
          {permission === 'write' && (
            <p className="sharing-note sharing-warn" data-testid="share-write-link-flag">
              {'// each URL holder becomes a writer after conversion, with no owner step'}
            </p>
          )}
        </>
      )}

      {fresh !== null && (
        <div className="sharing-fresh" data-testid="invite-link">
          <CopyableValue value={fresh} label="invite link" />
          <p className="sharing-note sharing-warn" data-testid="invite-link-bearer">
            {'// shown once — copy it now. whoever holds this link joins with no step from you'}
          </p>
        </div>
      )}

      <div className="sharing-chips" data-testid="share-link-chips">
        <span className="dialog-label">links</span>
        {scope.inviteLinks.length === 0 && <span className="sharing-note">{'// none'}</span>}
        {scope.inviteLinks.map((link) => (
          <LinkChip
            key={tagKey(link)}
            link={link}
            busy={busy}
            onRevoke={() => {
              actions.clearError();
              setConfirming(tagKey(link));
            }}
          />
        ))}
      </div>

      {chosen !== null && (
        <RevokeLinkPrompt
          link={chosen}
          scope={scope}
          actions={actions}
          busy={busy}
          onDone={() => setConfirming(null)}
        />
      )}
    </div>
  );
}

function tagKey(link: SharingInviteLinkDescriptor): string {
  return toHex(link.tag);
}

function LinkChip({
  link,
  busy,
  onRevoke,
}: {
  link: SharingInviteLinkDescriptor;
  busy: boolean;
  onRevoke: () => void;
}) {
  const pending = plural(link.pendingClaims, 'claim');
  const classes = ['sharing-chip'];
  if (link.expired) classes.push('sharing-chip--expired');
  if (link.permission === 'write') classes.push('sharing-chip--write');
  return (
    <span className={classes.join(' ')} data-testid="share-link-chip">
      <span data-testid="share-link-summary">
        {`${accessLabel(link.permission)} · ${expiryLabel(link.expired, link.expiresAt)} · admits ${link.admissionCap}`}
      </span>
      {pending !== null && (
        <span className="sharing-dim" data-testid="share-pending-claims">
          {`· ${pending} waiting`}
        </span>
      )}
      {link.contactBudgetFull && (
        <span
          className="sharing-warn"
          title="this link's claims hold its whole contact share, so none joins until a revoke"
          data-testid="share-link-full"
        >
          · full
        </span>
      )}
      <button
        type="button"
        aria-label={`revoke ${linkLabel(link)}`}
        onClick={onRevoke}
        disabled={busy}
        data-testid="share-revoke-link"
      >
        ×
      </button>
    </span>
  );
}

function RevokeLinkPrompt({
  link,
  scope,
  actions,
  busy,
  onDone,
}: {
  link: SharingInviteLinkDescriptor;
  scope: ScopeSharing;
  actions: SharingActions;
  busy: boolean;
  onDone: () => void;
}) {
  const [removeGrantees, setRemoveGrantees] = useState(false);
  const joined = joinedThrough(scope.grants, link);
  const people = joined.length === 1 ? '1 person' : `${joined.length} people`;

  const revoke = () =>
    void actions.revokeInviteLink(link.tag, { removeGrantees }).then((revoked) => {
      if (revoked) onDone();
    });

  return (
    <div className="sharing-confirm" role="alertdialog" data-testid="share-link-revoke-prompt">
      <p className="sharing-confirm-title">{`revoke the ${linkLabel(link)}?`}</p>
      <p className="sharing-note">{'// no one can join through it after this'}</p>
      {joined.length > 0 && (
        <>
          <p className="sharing-note" data-testid="share-link-keepers">
            {`// ${removeGrantees ? 'these lose access' : 'these keep access'}: ${joined
              .map((grant) => `${granteeLabel(grant)} (${grant.fingerprint ?? 'no fingerprint'})`)
              .join(', ')}`}
          </p>
          <label className="sharing-check">
            <input
              type="checkbox"
              checked={removeGrantees}
              onChange={(event) => setRemoveGrantees(event.target.checked)}
              disabled={busy}
              data-testid="share-link-remove-grantees"
            />
            {`also remove the ${people} who joined through it`}
          </label>
        </>
      )}
      <div className="dialog-actions">
        <button
          type="button"
          className="dialog-button"
          onClick={onDone}
          disabled={busy}
          data-testid="share-link-revoke-cancel"
        >
          keep
        </button>
        <button
          type="button"
          className="dialog-button dialog-button--danger"
          onClick={revoke}
          disabled={busy}
          data-testid="share-link-revoke-confirm"
        >
          {actions.busy === 'revokeInviteLink' ? 'revoking...' : 'revoke link'}
        </button>
      </div>
    </div>
  );
}
