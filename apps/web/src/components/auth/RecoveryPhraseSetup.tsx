import { useState } from 'react';
import { useAuth } from '../../auth/useAuth';
import { Modal } from '../ui/Modal';

type Step = 'explain' | 'reveal' | 'done';

/**
 * Enrollment: turn the factor policy on and show the phrase once (ADR 0009 D2).
 * The words are dropped the moment the member confirms they hold them, so the
 * dialog carries them for the reveal step and no longer.
 */
export function RecoveryPhraseSetup({ onClose }: { onClose: () => void }) {
  const { enrollRecoveryPhrase, isBusy, error } = useAuth();
  const [step, setStep] = useState<Step>('explain');
  const [words, setWords] = useState<string[]>([]);
  const [held, setHeld] = useState(false);
  const [warning, setWarning] = useState<string | null>(null);

  const enroll = async () => {
    try {
      const enrolled = await enrollRecoveryPhrase();
      setWords(enrolled.phrase.split(' '));
      setWarning(enrolled.warning);
      setStep('reveal');
    } catch {
      // `useAuth` already surfaces the failure as `error`, which `Modal` renders.
    }
  };

  // Past the cut the hashed cloud share is gone and these words are the
  // account's only spare key, so no dismissal discards them unacknowledged.
  const dismissible = step !== 'reveal' || held;

  return (
    <Modal
      onClose={onClose}
      title="recovery phrase"
      error={error}
      busy={isBusy}
      dismissible={dismissible}
    >
      {step === 'explain' && (
        <div className="dialog-content" data-testid="recovery-setup-explain">
          <p className="dialog-message">
            a recovery phrase is the only way back into your vault on a device that holds no key.
            CipherBox cannot restore it for you — nobody but you ever sees it.
          </p>
          <p className="dialog-message">
            you will be shown 24 words once. write them down before continuing.
          </p>
          <div className="dialog-actions">
            <button
              type="button"
              className="dialog-button dialog-button--primary"
              data-testid="recovery-setup-start"
              disabled={isBusy}
              onClick={() => void enroll()}
            >
              {isBusy ? 'generating...' : 'generate my phrase'}
            </button>
          </div>
        </div>
      )}

      {step === 'reveal' && (
        <div className="dialog-content" data-testid="recovery-setup-reveal">
          <ol className="recovery-phrase-grid" data-testid="recovery-phrase-grid">
            {words.map((word, index) => (
              <li key={`${String(index)}-${word}`} className="recovery-phrase-cell">
                {word}
              </li>
            ))}
          </ol>
          <p className="dialog-error">
            anyone holding these words can open your vault. keep them offline.
          </p>
          {warning && (
            <p className="dialog-error" role="alert" data-testid="recovery-setup-warning">
              {warning} — write the phrase down either way.
            </p>
          )}
          <label className="recovery-ack">
            <input
              type="checkbox"
              data-testid="recovery-setup-acknowledge"
              checked={held}
              onChange={(event) => setHeld(event.target.checked)}
            />
            i have written the phrase down
          </label>
          <div className="dialog-actions">
            <button
              type="button"
              className="dialog-button dialog-button--primary"
              data-testid="recovery-setup-confirm"
              disabled={!held}
              onClick={() => {
                setWords([]);
                setStep('done');
              }}
            >
              done
            </button>
          </div>
        </div>
      )}

      {step === 'done' && (
        <div className="dialog-content" data-testid="recovery-setup-done">
          <p className="dialog-message">
            the recovery phrase is on. sign in on a new device with those 24 words.
          </p>
          <div className="dialog-actions">
            <button
              type="button"
              className="dialog-button"
              data-testid="recovery-setup-close"
              onClick={onClose}
            >
              close
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}
