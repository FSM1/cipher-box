import { useEffect, useState } from 'react';
import { useAuth } from '../../auth/useAuth';
import { errorMessage } from '../../lib/errorMessage';
import { Modal } from '../ui/Modal';

type Step = 'explain' | 'reveal' | 'done';

/**
 * Enrollment: turn the factor policy on and show the phrase once (ADR 0009 D2).
 * The phrase is dropped the moment the member confirms they hold it, and again
 * on unmount, so closing the dialog is what ends its lifetime.
 */
export function RecoveryPhraseSetup({ onClose }: { onClose: () => void }) {
  const { enrollRecoveryPhrase } = useAuth();
  const [step, setStep] = useState<Step>('explain');
  const [words, setWords] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [held, setHeld] = useState(false);

  useEffect(() => () => setWords([]), []);

  const enroll = async () => {
    setBusy(true);
    setError(null);
    try {
      setWords((await enrollRecoveryPhrase()).split(' '));
      setStep('reveal');
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal onClose={onClose} title="recovery phrase" error={error} busy={busy}>
      {step === 'explain' && (
        <div data-testid="recovery-setup-explain">
          <p>
            a recovery phrase is the only way back into your vault on a device that holds no key.
            CipherBox cannot restore it for you — nobody but you ever sees it.
          </p>
          <p>you will be shown 24 words once. write them down before continuing.</p>
          <button
            type="button"
            data-testid="recovery-setup-start"
            disabled={busy}
            onClick={() => void enroll()}
          >
            {busy ? 'generating...' : 'generate my phrase'}
          </button>
        </div>
      )}

      {step === 'reveal' && (
        <div data-testid="recovery-setup-reveal">
          <ol className="recovery-phrase-grid" data-testid="recovery-phrase-grid">
            {words.map((word, index) => (
              <li key={`${String(index)}-${word}`} className="recovery-phrase-cell">
                {word}
              </li>
            ))}
          </ol>
          <p className="recovery-warning">
            anyone holding these words can open your vault. keep them offline.
          </p>
          <label className="recovery-ack">
            <input
              type="checkbox"
              data-testid="recovery-setup-acknowledge"
              checked={held}
              onChange={(event) => setHeld(event.target.checked)}
            />
            i have written the phrase down
          </label>
          <button
            type="button"
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
      )}

      {step === 'done' && (
        <div data-testid="recovery-setup-done">
          <p>the recovery phrase is on. sign in on a new device with those 24 words.</p>
          <button type="button" data-testid="recovery-setup-close" onClick={onClose}>
            close
          </button>
        </div>
      )}
    </Modal>
  );
}
