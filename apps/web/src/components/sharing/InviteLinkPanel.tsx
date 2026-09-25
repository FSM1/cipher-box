import type { SharingActions } from '../../hooks/useSharingActions';
import {
  expiryLabel,
  inviteLinkState,
  LINK_LIFETIMES,
  type LinkLifetime,
} from '../../sharing/inviteLink';
import { refusalLabel } from '../../sharing/shareRefusals';
import { plural } from '../../vault/selection';
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
 * Which of the three applies is `inviteLinkState`'s call, not this component's.
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
    case 'live': {
      const pending = plural(state.link.pendingClaims, 'claim');
      return (
        <div className="dialog-content" data-testid="share-live-link">
          <p className="sharing-note" data-testid="share-live-link-expiry">
            {`// a link stands here — ${expiryLabel(state.link.expired, state.link.expiresAt)}`}
          </p>
          {pending !== null && (
            <p className="sharing-note" data-testid="share-pending-claims">
              {`// ${pending} to convert`}
            </p>
          )}
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
            onClick={() => void actions.revokeInviteLink(state.link.tag)}
            disabled={busy}
            data-testid="share-revoke-link"
          >
            {actions.busy === 'revokeInviteLink' ? 'revoking...' : 'revoke link'}
          </button>
        </div>
      );
    }

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
