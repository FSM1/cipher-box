import { useEffect, useState } from 'react';
import { EmailLoginForm, LoginError } from '@cipherbox/auth-ui';
import { useIdentity } from '../../auth/IdentityProvider';
import { useAuth } from '../../auth/useAuth';
import { DeviceApprovalWait } from './DeviceApprovalWait';
import { GoogleLoginButton } from './GoogleLoginButton';
import { RecoveryPhraseLogin } from './RecoveryPhraseLogin';
import { SignedInElsewhere } from './SignedInElsewhere';
import { WalletLoginButton } from './WalletLoginButton';

/**
 * How a login held at the factor policy is finished. Both routes end the same
 * way; the phrase is the one that needs no second device (ADR 0009 D2).
 */
type RecoveryRoute = 'choose' | 'approve' | 'phrase';

/**
 * Every web login method, as the front door and the invite route both render
 * it. Each method completes in the page and never navigates, so a route that
 * holds a capability in its address keeps it across the sign-in. Every method
 * is a first login: each mints a CipherBox identity token and reaches the same
 * derived key (ADR 0008).
 */
export function SignInPanel() {
  const {
    isReady,
    isBusy,
    error,
    heldElsewhere,
    loginWithGoogle,
    sendEmailCode,
    loginWithEmailCode,
    walletNonce,
    loginWithWallet,
    recoveryRequired,
  } = useAuth();
  const { googleClientId } = useIdentity();
  const [route, setRoute] = useState<RecoveryRoute>('choose');

  // A resolved prompt leaves no route behind, so the next one starts at the ask.
  useEffect(() => {
    if (!recoveryRequired) setRoute('choose');
  }, [recoveryRequired]);

  // `useAuth` already surfaces the failure as `error`.
  const dispatch = (login: Promise<void>) => void login.catch(() => undefined);

  function heldAtPolicy() {
    if (route === 'phrase') return <RecoveryPhraseLogin />;
    if (route === 'approve') {
      return (
        <DeviceApprovalWait
          onUseRecoveryPhrase={() => setRoute('phrase')}
          onCancel={() => setRoute('choose')}
        />
      );
    }
    return (
      <div className="recovery-panel" data-testid="recovery-choice">
        <h2>one more step</h2>
        <p className="login-description">
          this device holds no key for your account. approve it from a device you already use, or
          enter your recovery phrase.
        </p>
        <div className="recovery-actions">
          <button
            type="button"
            className="terminal-btn terminal-btn--filled"
            onClick={() => setRoute('approve')}
            data-testid="recovery-choose-approve"
          >
            approve from a device you already use
          </button>
          <button
            type="button"
            className="terminal-btn"
            onClick={() => setRoute('phrase')}
            data-testid="recovery-choose-phrase"
          >
            use your recovery phrase
          </button>
        </div>
      </div>
    );
  }

  return (
    <>
      {recoveryRequired ? (
        heldAtPolicy()
      ) : (
        <div className="login-methods" data-testid="sign-in-methods">
          <GoogleLoginButton
            clientId={googleClientId}
            onCredential={(idToken) => dispatch(loginWithGoogle(idToken))}
            disabled={!isReady}
            busy={isBusy}
          />

          <div className="login-divider">
            <span>// or</span>
          </div>

          <EmailLoginForm
            onSendCode={sendEmailCode}
            onVerify={loginWithEmailCode}
            disabled={!isReady}
            busy={isBusy}
          />

          <div className="login-divider">
            <span>// or</span>
          </div>

          <WalletLoginButton
            requestNonce={walletNonce}
            onLogin={loginWithWallet}
            disabled={!isReady || isBusy}
          />
        </div>
      )}

      {heldElsewhere && <SignedInElsewhere heldBy={heldElsewhere.heldBy} />}
      {error && !recoveryRequired && <LoginError message={error} />}
    </>
  );
}
