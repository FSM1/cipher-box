import { useCallback, useState } from 'react';
import { useMfa } from '../../hooks/useMfa';
import { RecoveryPhraseGrid } from './RecoveryPhraseGrid';

type MfaEnrollmentWizardProps = {
  onComplete: () => void;
  onCancel: () => void;
};

type WizardStep = 1 | 2 | 3;

/**
 * Step-by-step MFA enrollment wizard.
 *
 * Step 1: Explain what MFA does and that it cannot be undone.
 * Step 2: Enable MFA, display recovery phrase, require acknowledgment.
 * Step 3: Confirmation that MFA is enabled with factor count.
 */
export function MfaEnrollmentWizard({ onComplete, onCancel }: MfaEnrollmentWizardProps) {
  const { enableMfa, factorCount, threshold } = useMfa();

  const [step, setStep] = useState<WizardStep>(1);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mnemonic, setMnemonic] = useState<string[]>([]);
  const [acknowledged, setAcknowledged] = useState(false);

  const handleEnableMfa = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const phrase = await enableMfa();
      setMnemonic(phrase.split(' '));
      setIsLoading(false);
    } catch (err) {
      setIsLoading(false);
      setError(err instanceof Error ? err.message : 'Failed to enable MFA');
    }
  }, [enableMfa]);

  const handleGoToStep2 = useCallback(() => {
    setStep(2);
    handleEnableMfa();
  }, [handleEnableMfa]);

  const handleGoToStep3 = useCallback(() => {
    setStep(3);
  }, []);

  const handleGoBackToStep1 = useCallback(() => {
    setStep(1);
  }, []);

  const toggleAcknowledged = useCallback(() => {
    setAcknowledged((prev) => !prev);
  }, []);

  const handleCheckboxKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggleAcknowledged();
      }
    },
    [toggleAcknowledged]
  );

  return (
    <div className="mfa-wizard">
      {/* Step indicator */}
      <div className="mfa-wizard-step-indicator">
        <span className="mfa-wizard-step-label">{'step ' + step + ' of 3'}</span>
        <div className="mfa-wizard-progress-bar">
          <div className={`mfa-wizard-progress-segment ${step >= 1 ? 'complete' : ''}`} />
          <div className={`mfa-wizard-progress-segment ${step >= 2 ? 'complete' : ''}`} />
          <div className={`mfa-wizard-progress-segment ${step >= 3 ? 'complete' : ''}`} />
        </div>
      </div>

      {/* Step 1: Explain MFA */}
      {step === 1 && (
        <div className="mfa-wizard-step">
          <h3 className="mfa-wizard-step-title">{'// enable multi-factor authentication'}</h3>
          <div className="mfa-wizard-step-content">
            <p className="mfa-wizard-text">
              MFA adds an extra layer of security to your vault. When enabled, logging in from a new
              device will require approval from an existing device or your recovery phrase.
            </p>
            <p className="mfa-wizard-text">
              Known devices will continue to log in seamlessly -- MFA only challenges new or unknown
              devices.
            </p>
            <div className="mfa-wizard-warning-box">
              <p className="mfa-wizard-warning-text">
                Enabling MFA is permanent and cannot be undone. You can manage individual factors
                (devices, recovery phrase) after enrollment, but MFA itself stays active.
              </p>
            </div>
          </div>
          <div className="mfa-wizard-actions">
            <button
              type="button"
              className="mfa-wizard-btn mfa-wizard-btn-secondary"
              onClick={onCancel}
            >
              --cancel
            </button>
            <button
              type="button"
              className="mfa-wizard-btn mfa-wizard-btn-primary"
              onClick={handleGoToStep2}
            >
              --continue
            </button>
          </div>
        </div>
      )}

      {/* Step 2: Recovery Phrase */}
      {step === 2 && (
        <div className="mfa-wizard-step">
          <h3 className="mfa-wizard-step-title">{'// recovery phrase'}</h3>
          <div className="mfa-wizard-step-content">
            {isLoading && (
              <div className="mfa-wizard-loading">
                <span className="mfa-wizard-spinner" aria-hidden="true" />
                enabling MFA and generating recovery phrase...
              </div>
            )}

            {error && (
              <div className="mfa-wizard-error" role="alert">
                <p>{error}</p>
                <button
                  type="button"
                  className="mfa-wizard-btn mfa-wizard-btn-secondary"
                  onClick={handleEnableMfa}
                >
                  --retry
                </button>
              </div>
            )}

            {!isLoading && !error && mnemonic.length > 0 && (
              <>
                <p className="mfa-wizard-text">
                  Write down these 24 words in order and store them in a safe place. This is the
                  only way to recover your vault if you lose all your devices.
                </p>

                <RecoveryPhraseGrid words={mnemonic} />

                <div className="mfa-wizard-danger-box" role="alert">
                  If you lose this phrase and all your devices, your account CANNOT be recovered.
                </div>

                <div
                  className={`mfa-wizard-checkbox ${acknowledged ? 'checked' : ''}`}
                  role="checkbox"
                  aria-checked={acknowledged}
                  tabIndex={0}
                  onClick={toggleAcknowledged}
                  onKeyDown={handleCheckboxKeyDown}
                >
                  <span className="mfa-wizard-checkbox-box" aria-hidden="true">
                    {acknowledged ? '[x]' : '[ ]'}
                  </span>
                  <span className="mfa-wizard-checkbox-label">
                    I have written down and safely stored my recovery phrase
                  </span>
                </div>
              </>
            )}
          </div>

          <div className="mfa-wizard-actions">
            <button
              type="button"
              className="mfa-wizard-btn mfa-wizard-btn-secondary"
              onClick={handleGoBackToStep1}
            >
              --back
            </button>
            <button
              type="button"
              className="mfa-wizard-btn mfa-wizard-btn-primary"
              onClick={handleGoToStep3}
              disabled={!acknowledged || isLoading || !!error}
            >
              --continue
            </button>
          </div>
        </div>
      )}

      {/* Step 3: Success */}
      {step === 3 && (
        <div className="mfa-wizard-step">
          <h3 className="mfa-wizard-step-title">{'// mfa enabled'}</h3>
          <div className="mfa-wizard-step-content">
            <div className="mfa-wizard-success">
              <span className="mfa-wizard-success-icon" aria-hidden="true">
                [OK]
              </span>
              <p className="mfa-wizard-text">
                Multi-factor authentication has been successfully enabled on your account.
              </p>
            </div>
            <div className="mfa-wizard-factor-summary">
              <span className="mfa-wizard-factor-count">
                {factorCount} factors active, {threshold}/{factorCount} threshold
              </span>
            </div>
            <p className="mfa-wizard-text mfa-wizard-text-dim">
              New devices will require approval from an existing device or your recovery phrase. You
              can manage your factors from Settings &gt; Security at any time.
            </p>
          </div>
          <div className="mfa-wizard-actions">
            <button
              type="button"
              className="mfa-wizard-btn mfa-wizard-btn-primary"
              onClick={onComplete}
            >
              --done
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
