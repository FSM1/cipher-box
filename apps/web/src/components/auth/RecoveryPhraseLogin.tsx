import { RecoveryPhraseForm } from '@cipherbox/auth-ui';
import { useAuth } from '../../auth/useAuth';

/** The shared phrase form over this host's auth wiring (ADR 0009 D2). */
export function RecoveryPhraseLogin() {
  const { loginWithRecoveryPhrase, cancelRecovery, isBusy, error } = useAuth();
  return (
    <RecoveryPhraseForm
      onSubmit={loginWithRecoveryPhrase}
      onCancel={() => void cancelRecovery()}
      busy={isBusy}
      error={error}
    />
  );
}
