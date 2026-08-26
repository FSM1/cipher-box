import type { SharingActions } from '../../hooks/useSharingActions';
import {
  expiryLabel,
  inviteLinkState,
  LINK_LIFETIMES,
  refusalLabel,
  type LinkLifetime,
} from '../../sharing/inviteLink';
import type { ScopeSharing } from '../../stores/sharing.store';

interface InviteLinkPanelProps {
  /** The scope's own state, as the engine last reported it. */
  scope: ScopeSharing;
  actions: SharingActions;
  busy: boolean;
  lifetime: LinkLifetime;
  onLifetime: (next: LinkLifetime) => void;
  onMint: () => void;
}

/**
 * The link half of the share dialog: the standing of the link a scope carries
 * and the owner's actions on it, or the mint where the engine would take one.
 * Which of the four applies is `inviteLinkState`'s call, not this component's.
 */
export function InviteLinkPanel({
  scope,
  actions,
  busy,
  lifetime,
  onLifetime,
  onMint,
}: InviteLinkPanelProps) {
  const state = inviteLinkState(scope);

  switch (state.kind) {
    case 'unavailable':
      return (
        <p className="sharing-note" data-testid="share-links-unavailable">
          {'// link standing unavailable'}
        </p>
      );

    case 'live':
      return (
        <div className="dialog-content" data-testid="share-live-link">
          <p className="sharing-note" data-testid="share-live-link-expiry">
            {`// a link stands here — ${expiryLabel(state.links)}`}
          </p>
          <button
            type="button"
            className="dialog-button"
            onClick={() => void actions.convertInviteClaims()}
            disabled={busy}
            data-testid="share-convert-claims"
          >
            {actions.busy === 'convertInviteClaims' ? 'converting...' : 'convert claims'}
          </button>
          <button
            type="button"
            className="dialog-button dialog-button--danger"
            onClick={() => void actions.revokeInviteLink()}
            disabled={busy}
            data-testid="share-revoke-link"
          >
            {actions.busy === 'revokeInviteLink' ? 'revoking...' : 'revoke link'}
          </button>
        </div>
      );

    case 'mintable':
      return (
        <div className="dialog-content">
          <label className="dialog-label" htmlFor="share-link-lifetime">
            link expires
          </label>
          <select
            id="share-link-lifetime"
            className="dialog-input"
            value={lifetime}
            onChange={(event) => onLifetime(event.target.value as LinkLifetime)}
            disabled={busy}
          >
            {Object.keys(LINK_LIFETIMES).map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="dialog-button"
            onClick={onMint}
            disabled={busy}
            data-testid="share-mint-link"
          >
            {actions.busy === 'createInviteLink' ? 'minting...' : 'mint invite link'}
          </button>
        </div>
      );

    case 'refused':
      return (
        <p className="sharing-note" data-testid="share-no-mint" data-check={state.check}>
          {`// ${refusalLabel(state.check)}`}
        </p>
      );
  }
}

/** Offers the prune the engine's spent count says there is something to drop. */
export function SpentLinkRecords({
  scope,
  actions,
  busy,
}: Pick<InviteLinkPanelProps, 'scope' | 'actions' | 'busy'>) {
  const spent = scope.inviteLinks?.spent ?? 0;
  if (spent === 0) return null;

  return (
    <button
      type="button"
      className="dialog-button"
      onClick={() => void actions.pruneInviteLinks()}
      disabled={busy}
      data-testid="share-prune-links"
    >
      {actions.busy === 'pruneInviteLinks'
        ? 'pruning...'
        : `forget ${spent} spent link record${spent === 1 ? '' : 's'}`}
    </button>
  );
}
