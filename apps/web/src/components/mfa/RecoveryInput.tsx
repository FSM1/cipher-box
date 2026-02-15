import { useCallback, useState } from 'react';
import { useMfa } from '../../hooks/useMfa';
import { useDeviceApproval } from '../../hooks/useDeviceApproval';

type RecoveryInputProps = {
  onRecoveryComplete: () => void;
  onBack: () => void;
};

/**
 * Recovery phrase input form for REQUIRED_SHARE state.
 * Accepts a 24-word BIP39 mnemonic to recover account access
 * on a new device.
 *
 * On successful recovery:
 * 1. Cancels any pending approval request (Pitfall 5)
 * 2. Creates a device factor for the new device
 * 3. Calls onRecoveryComplete to resume login
 */
export function RecoveryInput({ onRecoveryComplete, onBack }: RecoveryInputProps) {
  const { recoverWithMnemonic } = useMfa();
  const { cancelRequest } = useDeviceApproval();

  const [phrase, setPhrase] = useState('');
  const [isRecovering, setIsRecovering] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleRecover = useCallback(async () => {
    const trimmed = phrase.trim().toLowerCase();
    const words = trimmed.split(/\s+/);

    if (words.length !== 24) {
      setError(`Expected 24 words, got ${words.length}.`);
      return;
    }

    setIsRecovering(true);
    setError(null);

    try {
      // Recover using the mnemonic (inputs factor key + creates device factor)
      await recoverWithMnemonic(trimmed);

      // Cancel any pending approval request (RESEARCH.md Pitfall 5)
      await cancelRequest();

      onRecoveryComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Recovery failed. Please check your phrase.');
    } finally {
      setIsRecovering(false);
    }
  }, [phrase, recoverWithMnemonic, cancelRequest, onRecoveryComplete]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleRecover();
      }
    },
    [handleRecover]
  );

  return (
    <div className="recovery-input">
      <h2 className="recovery-input-title">{'// enter your recovery phrase'}</h2>

      <div className="recovery-input-content">
        <p className="recovery-input-description">
          Enter your 24-word recovery phrase to access your vault on this device.
        </p>

        <textarea
          className="recovery-input-textarea"
          value={phrase}
          onChange={(e) => setPhrase(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Enter your 24-word recovery phrase..."
          rows={4}
          disabled={isRecovering}
          autoFocus
          spellCheck={false}
          autoComplete="off"
          autoCapitalize="off"
        />

        {error && (
          <div className="recovery-input-error" role="alert">
            {error}
          </div>
        )}
      </div>

      <div className="recovery-input-actions">
        <button
          type="button"
          className="recovery-input-btn recovery-input-btn-secondary"
          onClick={onBack}
          disabled={isRecovering}
        >
          --back
        </button>
        <button
          type="button"
          className="recovery-input-btn recovery-input-btn-primary"
          onClick={handleRecover}
          disabled={isRecovering || !phrase.trim()}
        >
          {isRecovering ? 'recovering...' : '--recover'}
        </button>
      </div>
    </div>
  );
}
