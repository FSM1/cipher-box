import { useEffect, useState } from 'react';
import { EmailLoginForm, LoginError } from '@cipherbox/auth-ui';
import { useIdentity } from '../../auth/IdentityProvider';
import { useAuth } from '../../auth/useAuth';
import { authStore, useAuthState } from '../../stores/auth.store';
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
 * Every web login method, completed in place. Each is a first login: it mints
 * a CipherBox identity token and reaches the same derived key (ADR 0008).
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
  const { saveDevice } = useAuthState();
  const [route, setRoute] = useState<RecoveryRoute>('choose');

  // A resolved prompt leaves no route behind, so the next one starts at the ask.
  useEffect(() => {
    if (!recoveryRequired) setRoute('choose');
  }, [recoveryRequired]);

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
          <div>
            <label className="recovery-ack">
              <input
                type="checkbox"
                data-testid="save-device-checkbox"
                checked={saveDevice}
                onChange={(event) => authStore.saveDevice(event.target.checked)}
              />
              save this device
            </label>
            <p className="sharing-note">
              {'// a saved device can approve your sign-in on a new browser'}
            </p>
          </div>

          <GoogleLoginButton
            clientId={googleClientId}
            onCredential={loginWithGoogle}
            disabled={!isReady || isBusy}
          />

          <div className="login-divider">
            <span>// or</span>
          </div>

          <EmailLoginForm
            onSendCode={sendEmailCode}
            onVerify={loginWithEmailCode}
            disabled={!isReady || isBusy}
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
