import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { MAX_PASTED_CHARS, parseContactCode } from '../../sharing/contactCode';
import { browserContactScanner, type ContactScanner } from '../../sharing/contactScanner';
import { CopyableValue } from '../file-browser/details/DetailsPrimitives';

interface ContactImportFormProps {
  busy: boolean;
  /** Hex, or `null` until a sharing read has landed (`stores/sharing.store`). */
  ownContactCode: string | null;
  /** The camera seam; tests pass a fake rather than drive a live stream. */
  scanner?: ContactScanner;
  onCancel: () => void;
  onConfirm: (contactCode: Uint8Array) => void;
}

/** Idle, holding the camera, or carrying what the last scan came back with. */
type ScanState = 'idle' | 'scanning' | 'nothing-read' | 'no-camera';

/**
 * Both halves of a contact exchange: the code this member hands over, and the
 * peer's code by paste or by camera. Identity keys arrive only out-of-band
 * (blueprint/api.md "Contact exchange") and each code authenticates itself, so
 * this reads nothing inside either one.
 */
export function ContactImportForm({
  busy,
  ownContactCode,
  scanner = browserContactScanner,
  onCancel,
  onConfirm,
}: ContactImportFormProps) {
  const [pasted, setPasted] = useState('');
  const [scanState, setScanState] = useState<ScanState>('idle');
  const videoRef = useRef<HTMLVideoElement | null>(null);
  // Memoized: a mis-paste can be arbitrarily long, and this runs per keystroke.
  const code = useMemo(() => parseContactCode(pasted), [pasted]);
  const unreadable = pasted.trim() !== '' && code === null;
  const canScan = scanner.supported();

  // The dialog re-makes this each render; a re-run would drop the camera.
  const confirm = useRef(onConfirm);
  useEffect(() => {
    confirm.current = onConfirm;
  }, [onConfirm]);

  useEffect(() => {
    const video = videoRef.current;
    if (scanState !== 'scanning' || video === null) return;
    const holder = new AbortController();
    let live = true;
    scanner
      .scan({ video, signal: holder.signal })
      .then((text) => {
        if (!live) return;
        const scanned = text === null ? null : parseContactCode(text);
        if (scanned === null) {
          setScanState('nothing-read');
          return;
        }
        setScanState('idle');
        confirm.current(scanned);
      })
      .catch(() => {
        if (live) setScanState('no-camera');
      });
    return () => {
      live = false;
      holder.abort();
    };
  }, [scanState, scanner]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!busy && code !== null) onConfirm(code);
  };

  return (
    <form className="dialog-content" onSubmit={submit} data-testid="import-contact-form">
      <p className="dialog-label">your contact code</p>
      {ownContactCode === null ? (
        <p className="sharing-note">{'// no read has landed yet'}</p>
      ) : (
        <div data-testid="own-contact-code">
          <CopyableValue value={ownContactCode} label="your contact code" />
          <p className="sharing-note">{'// send this to them — an exchange needs both codes'}</p>
        </div>
      )}

      <label className="dialog-label" htmlFor="import-contact-code">
        their contact code
      </label>
      <textarea
        id="import-contact-code"
        className="dialog-input sharing-code-field"
        value={pasted}
        maxLength={MAX_PASTED_CHARS}
        onChange={(event) => setPasted(event.target.value)}
        disabled={busy}
        autoComplete="off"
        spellCheck={false}
        autoFocus
      />
      {unreadable && (
        <p className="sharing-note" data-testid="import-contact-unreadable">
          {'// that is not a contact code — paste it exactly as it was sent'}
        </p>
      )}

      {canScan && (
        <div className="dialog-content" data-testid="import-contact-scan-section">
          {scanState === 'scanning' ? (
            <>
              <video
                ref={videoRef}
                className="sharing-scan-preview"
                data-testid="import-contact-preview"
                muted
                playsInline
              />
              <button
                type="button"
                className="dialog-button"
                onClick={() => setScanState('idle')}
                data-testid="import-contact-scan-stop"
              >
                stop scanning
              </button>
            </>
          ) : (
            <button
              type="button"
              className="dialog-button"
              onClick={() => setScanState('scanning')}
              disabled={busy}
              data-testid="import-contact-scan"
            >
              scan a code
            </button>
          )}
          {scanState === 'nothing-read' && (
            <p className="sharing-note" data-testid="import-contact-nothing-read">
              {'// no code found — try again or paste it'}
            </p>
          )}
          {scanState === 'no-camera' && (
            <p className="sharing-note" data-testid="import-contact-no-camera">
              {'// the camera is not available — paste the code instead'}
            </p>
          )}
        </div>
      )}

      <div className="dialog-actions">
        <button
          type="button"
          className="dialog-button"
          onClick={onCancel}
          disabled={busy}
          data-testid="import-contact-cancel"
        >
          back
        </button>
        <button
          type="submit"
          className="dialog-button dialog-button--primary"
          disabled={busy || code === null}
          data-testid="import-contact-confirm"
        >
          {busy ? 'verifying...' : 'import'}
        </button>
      </div>
    </form>
  );
}
