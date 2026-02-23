import { useCallback, useEffect, useRef, useState } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { MatrixBackground } from '../components/MatrixBackground';
import { StagingBanner } from '../components/StagingBanner';
import { GoogleLoginButton } from '../components/auth/GoogleLoginButton';
import { EmailLoginForm } from '../components/auth/EmailLoginForm';
import { WalletLoginButton } from '../components/auth/WalletLoginButton';
import { DeviceWaitingScreen } from '../components/mfa/DeviceWaitingScreen';
import { RecoveryInput } from '../components/mfa/RecoveryInput';
import { checkInviteStatus, claimInvite } from '../services/invite.service';
import { useAuth } from '../hooks/useAuth';
import '../styles/invite-page.css';

/** State machine for invite page */
type InvitePageState = 'loading' | 'valid' | 'claiming' | 'claimed' | 'error';

/** Error reason for display */
type ErrorReason = 'expired' | 'claimed' | 'revoked' | 'invalid';

type MfaView = 'waiting' | 'recovery';

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
 * - Inline auth (Google, Email, Wallet) matching Login.tsx
 * - Auto-claim after authentication via useEffect watching isAuthenticated
 * - Error cards with red border for expired/claimed/revoked/invalid
 *
 * The ephemeral private key is read from the hash fragment query param
 * on initial render and stored in a ref (never in state, never logged).
 */
export function InvitePage() {
  const { token } = useParams<{ token: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const {
    isAuthenticated,
    isLoading,
    isRequiredShare,
    loginWithGoogle,
    loginWithEmail,
    loginWithWallet,
    completeRequiredShare,
  } = useAuth();

  // Store ephemeral key in ref -- not state (avoid re-render loss), never log
  const ephemeralKeyRef = useRef<string | null>(searchParams.get('key'));

  const [pageState, setPageState] = useState<InvitePageState>('loading');
  const [errorReason, setErrorReason] = useState<ErrorReason>('invalid');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [mfaView, setMfaView] = useState<MfaView>('waiting');

  // Track whether we've started claiming to prevent double-claim
  const claimingRef = useRef(false);

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

  // Auto-claim when authentication completes
  useEffect(() => {
    if (!isAuthenticated || pageState !== 'valid' || claimingRef.current) return;
    if (!token || !ephemeralKeyRef.current) return;

    claimingRef.current = true;
    setPageState('claiming');

    const ephemeralKeyHex = ephemeralKeyRef.current;

    claimInvite(token, ephemeralKeyHex)
      .then(() => {
        setPageState('claimed');
        // Zero the ephemeral key
        ephemeralKeyRef.current = null;
        // Navigate to shared after brief delay
        setTimeout(() => {
          navigate('/shared', { replace: true });
        }, 500);
      })
      .catch((err) => {
        const status = (err as { status?: number }).status;
        if (status === 409) {
          setErrorReason('claimed');
        } else if (status === 404) {
          setErrorReason('expired');
        } else {
          setErrorReason('invalid');
        }
        setPageState('error');
      })
      .finally(() => {
        // Always zero the ephemeral key
        ephemeralKeyRef.current = null;
      });
  }, [isAuthenticated, pageState, token, navigate]);

  // Auth callbacks -- match Login.tsx patterns
  const handleGoogleLogin = useCallback(
    async (googleIdToken: string) => {
      setLoginError(null);
      try {
        await loginWithGoogle(googleIdToken);
      } catch (err) {
        setLoginError(err instanceof Error ? err.message : 'Google login failed');
      }
    },
    [loginWithGoogle]
  );

  const handleEmailLogin = useCallback(
    async (email: string, otp: string) => {
      setLoginError(null);
      try {
        await loginWithEmail(email, otp);
      } catch (err) {
        setLoginError(err instanceof Error ? err.message : 'Email login failed');
      }
    },
    [loginWithEmail]
  );

  const handleWalletLogin = useCallback(
    async (cipherboxJwt: string, userId: string) => {
      setLoginError(null);
      try {
        await loginWithWallet(cipherboxJwt, userId);
      } catch (err) {
        setLoginError(err instanceof Error ? err.message : 'Wallet login failed');
      }
    },
    [loginWithWallet]
  );

  // MFA handlers -- match Login.tsx patterns
  const handleRecoveryFallback = useCallback(() => {
    setMfaView('recovery');
  }, []);

  const handleBackToWaiting = useCallback(() => {
    setMfaView('waiting');
  }, []);

  const handleRecoveryComplete = useCallback(async () => {
    try {
      await completeRequiredShare();
    } catch (err) {
      setLoginError(err instanceof Error ? err.message : 'Failed to complete login after recovery');
    }
  }, [completeRequiredShare]);

  const handleApprovalComplete = useCallback(() => {
    // Approval flow already called completeRequiredShare() inside the hook.
  }, []);

  // Shared card wrapper
  const isError = pageState === 'error';

  // Show loading state while auth is initializing
  if (isLoading && pageState === 'loading') {
    return (
      <>
        <StagingBanner variant="login" />
        <div className="invite-page">
          <MatrixBackground opacity={0.3} frameInterval={50} />
          <div className="invite-card">
            <h1 className="invite-card__title">CIPHERBOX</h1>
            <p className="invite-card__tagline">zero-knowledge encrypted storage</p>
            <div className="invite-card__loading">initializing...</div>
          </div>
        </div>
      </>
    );
  }

  // REQUIRED_SHARE state: show MFA challenge UI
  if (isRequiredShare && pageState === 'valid') {
    return (
      <>
        <StagingBanner variant="login" />
        <div className="invite-page">
          <MatrixBackground opacity={0.3} frameInterval={50} />
          <div className="invite-card">
            <h1 className="invite-card__title">CIPHERBOX</h1>
            <p className="invite-card__tagline">zero-knowledge encrypted storage</p>
            {mfaView === 'waiting' ? (
              <DeviceWaitingScreen
                onRecoveryFallback={handleRecoveryFallback}
                onApprovalComplete={handleApprovalComplete}
              />
            ) : (
              <RecoveryInput
                onRecoveryComplete={handleRecoveryComplete}
                onBack={handleBackToWaiting}
              />
            )}
            {loginError && (
              <div className="invite-card__login-error" role="alert" aria-live="polite">
                {loginError}
              </div>
            )}
          </div>
        </div>
      </>
    );
  }

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

          {/* Valid invite -- show branded message + auth */}
          {pageState === 'valid' && !isAuthenticated && (
            <>
              <p className="invite-card__message">someone shared a file with you</p>
              <p className="invite-card__sub-message">
                log in or create a CipherBox account to access this shared file
              </p>
              <div className="invite-card__auth-area">
                <div className="invite-card__auth-methods">
                  <GoogleLoginButton onLogin={handleGoogleLogin} disabled={isLoading} />
                  <div className="invite-card__auth-divider">
                    <span>{'// or'}</span>
                  </div>
                  <EmailLoginForm onLogin={handleEmailLogin} disabled={isLoading} />
                  <div className="invite-card__auth-divider">
                    <span>{'// or'}</span>
                  </div>
                  <WalletLoginButton onLogin={handleWalletLogin} disabled={isLoading} />
                </div>
              </div>
              {loginError && (
                <div className="invite-card__login-error" role="alert" aria-live="polite">
                  {loginError}
                </div>
              )}
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
