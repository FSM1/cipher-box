import { useEffect, useRef, useState } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { MatrixBackground } from '../components/MatrixBackground';
import { StagingBanner } from '../components/StagingBanner';
import { checkInviteStatus } from '../services/invite.service';
import '../styles/invite-page.css';

/** State machine for invite page */
export type InvitePageState = 'loading' | 'valid' | 'claiming' | 'claimed' | 'error';

/** Error reason for display */
type ErrorReason = 'expired' | 'claimed' | 'revoked' | 'invalid';

const ERROR_MESSAGES: Record<ErrorReason, string> = {
  expired: 'this link has expired',
  claimed: 'this link has already been claimed',
  revoked: 'this link has been revoked',
  invalid: 'invalid link',
};

/**
 * Invite landing page for share link recipients.
 *
 * Standalone page (no AppShell) with:
 * - Status check on mount via checkInviteStatus
 * - Branded card with login CTA for valid invites
 * - Error cards with red border for expired/claimed/revoked/invalid
 * - Auth integration and claim flow added in Task 3
 *
 * The ephemeral private key is read from the hash fragment query param
 * on initial render and stored in a ref (never in state, never logged).
 */
export function InvitePage() {
  const { token } = useParams<{ token: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  // Store ephemeral key in ref -- not state (avoid re-render loss), never log
  const ephemeralKeyRef = useRef<string | null>(searchParams.get('key'));

  const [pageState, setPageState] = useState<InvitePageState>('loading');
  const [errorReason, setErrorReason] = useState<ErrorReason>('invalid');

  // Validate URL params and check invite status on mount
  useEffect(() => {
    if (!token || !ephemeralKeyRef.current) {
      setErrorReason('invalid');
      setPageState('error');
      return;
    }

    let cancelled = false;

    checkInviteStatus(token).then((status) => {
      if (cancelled) return;

      if (status === 'active') {
        setPageState('valid');
      } else {
        setErrorReason(status as ErrorReason);
        setPageState('error');
      }
    });

    return () => {
      cancelled = true;
    };
  }, [token]);

  // Shared card wrapper
  const isError = pageState === 'error';

  return (
    <>
      <StagingBanner variant="login" />
      <div className="invite-page">
        <MatrixBackground opacity={0.3} frameInterval={50} />
        <div className={`invite-card${isError ? ' invite-card--error' : ''}`}>
          <h1 className="invite-card__title">CIPHERBOX</h1>
          <p className="invite-card__tagline">zero-knowledge encrypted storage</p>

          {/* Loading state */}
          {pageState === 'loading' && (
            <div className="invite-card__loading">checking invite...</div>
          )}

          {/* Valid invite -- show branded message + auth area placeholder */}
          {pageState === 'valid' && (
            <>
              <p className="invite-card__message">someone shared a file with you</p>
              <p className="invite-card__sub-message">
                log in or create a CipherBox account to access this shared file
              </p>
              <div className="invite-card__auth-area">{/* Auth components added in Task 3 */}</div>
            </>
          )}

          {/* Claiming state */}
          {pageState === 'claiming' && (
            <div className="invite-card__claiming">claiming your share...</div>
          )}

          {/* Claimed state -- brief success before redirect */}
          {pageState === 'claimed' && (
            <div className="invite-card__success">share claimed -- redirecting...</div>
          )}

          {/* Error state */}
          {pageState === 'error' && (
            <>
              <div className="invite-card__error">{ERROR_MESSAGES[errorReason]}</div>
              <button type="button" className="invite-card__home-btn" onClick={() => navigate('/')}>
                {'[GO HOME]'}
              </button>
            </>
          )}
        </div>
      </div>
    </>
  );
}
