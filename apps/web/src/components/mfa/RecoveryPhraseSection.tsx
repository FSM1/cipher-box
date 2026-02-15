import { useCallback, useMemo, useState } from 'react';
import { FactorKeyTypeShareDescription } from '@web3auth/mpc-core-kit';
import { useMfa } from '../../hooks/useMfa';
import { RecoveryPhraseGrid } from './RecoveryPhraseGrid';

/**
 * Recovery phrase status and regeneration section for the Security tab.
 *
 * Shows whether a recovery factor is active, allows regeneration with
 * confirmation, and displays the new phrase with acknowledgment checkbox.
 */
export function RecoveryPhraseSection() {
  const { getFactors, regenerateRecoveryPhrase } = useMfa();

  const [showConfirm, setShowConfirm] = useState(false);
  const [isRegenerating, setIsRegenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newPhrase, setNewPhrase] = useState<string[] | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);

  const factors = useMemo(() => getFactors(), [getFactors]);
  const hasRecoveryFactor = factors.some(
    (f) => f.type === FactorKeyTypeShareDescription.SeedPhrase || f.type === 'seedPhrase'
  );

  const handleRegenerate = useCallback(async () => {
    setIsRegenerating(true);
    setError(null);
    try {
      const mnemonic = await regenerateRecoveryPhrase();
      setNewPhrase(mnemonic.split(' '));
      setShowConfirm(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to regenerate recovery phrase');
    } finally {
      setIsRegenerating(false);
    }
  }, [regenerateRecoveryPhrase]);

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

  const handleDismissPhrase = useCallback(() => {
    setNewPhrase(null);
    setAcknowledged(false);
  }, []);

  return (
    <div className="recovery-section">
      {/* Status */}
      <div className="recovery-section-status">
        <span
          className={`recovery-section-status-dot ${hasRecoveryFactor ? '' : 'inactive'}`}
          aria-hidden="true"
        />
        <span className="recovery-section-status-label">
          {hasRecoveryFactor ? 'recovery phrase active' : 'no recovery phrase'}
        </span>
      </div>

      {/* Error display */}
      {error && (
        <div className="linked-methods-error" role="alert">
          {error}
          <button
            type="button"
            onClick={() => setError(null)}
            className="linked-methods-error-dismiss"
            aria-label="Dismiss error"
          >
            [x]
          </button>
        </div>
      )}

      {/* Confirmation dialog for regeneration */}
      {showConfirm && (
        <div className="recovery-section-confirm">
          <p className="recovery-section-confirm-text">
            This will invalidate your current recovery phrase. Any written copies of the old phrase
            will no longer work. Are you sure?
          </p>
          <div className="recovery-section-confirm-actions">
            <button
              type="button"
              className="recovery-section-confirm-btn danger"
              onClick={handleRegenerate}
              disabled={isRegenerating}
            >
              {isRegenerating ? 'regenerating...' : '--confirm-regenerate'}
            </button>
            <button
              type="button"
              className="recovery-section-confirm-btn cancel"
              onClick={() => setShowConfirm(false)}
              disabled={isRegenerating}
            >
              --cancel
            </button>
          </div>
        </div>
      )}

      {/* New phrase display after regeneration */}
      {newPhrase && (
        <div className="recovery-section-new-phrase">
          <h4 className="recovery-section-new-phrase-title">{'// new recovery phrase'}</h4>
          <RecoveryPhraseGrid words={newPhrase} />

          <div className="mfa-wizard-danger-box" role="alert">
            Your previous recovery phrase is now invalid. Write down this new phrase and store it
            safely.
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
              I have written down and safely stored my new recovery phrase
            </span>
          </div>

          {acknowledged && (
            <button
              type="button"
              className="recovery-section-btn"
              onClick={handleDismissPhrase}
              style={{ marginTop: '8px' }}
            >
              --done
            </button>
          )}
        </div>
      )}

      {/* Regenerate button (hidden when showing confirm or new phrase) */}
      {!showConfirm && !newPhrase && hasRecoveryFactor && (
        <div className="recovery-section-actions">
          <button
            type="button"
            className="recovery-section-btn"
            onClick={() => setShowConfirm(true)}
          >
            --regenerate
          </button>
        </div>
      )}
    </div>
  );
}
