import { useCallback, useEffect, useId, useRef, type ReactNode } from 'react';
import { Portal } from './Portal';

const FOCUSABLE = 'button:not(:disabled), [href], input:not(:disabled), textarea, [tabindex="0"]';

interface ModalProps {
  onClose: () => void;
  title: string;
  /** Variant class on the backdrop, for wide dialogs like the previews. */
  className?: string;
  /** A failure to report where the backdrop cannot hide it. */
  error?: string | null;
  /**
   * A command is in flight. Dismissal is refused for as long as it is: the
   * dialog owns that command's outcome, and a dismissed one would report its
   * rejection into whatever dialog had replaced it.
   */
  busy?: boolean;
  /**
   * Whether the dialog may be dismissed at all. A step holding something the
   * member cannot be shown a second time clears this, and Escape, the backdrop,
   * and the close control all stop discarding it.
   */
  dismissible?: boolean;
  children: ReactNode;
}

/**
 * The one modal shell: a portalled backdrop, an Escape/backdrop close, and a
 * Tab cycle that cannot leave the dialog. Callers mount it to open it, so
 * unmounting is what resets a dialog's own state.
 */
export function Modal({
  onClose,
  title,
  className,
  error,
  busy = false,
  dismissible = true,
  children,
}: ModalProps) {
  const refuseClose = busy || !dismissible;
  const dialogRef = useRef<HTMLDivElement>(null);
  const opener = useRef<Element | null>(null);
  const titleId = useId();
  // Callers pass a fresh closure per render; re-running the effect on it would
  // pull focus out of the field being typed in every time a pull lands.
  const close = useRef(onClose);
  close.current = onClose;
  const locked = useRef(refuseClose);
  locked.current = refuseClose;

  const focusable = useCallback(
    () => [...(dialogRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? [])],
    []
  );

  useEffect(() => {
    opener.current = document.activeElement;
    // A field the dialog autofocused keeps it; otherwise focus enters at the top.
    if (!dialogRef.current?.contains(document.activeElement)) focusable()[0]?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        if (!locked.current) close.current();
        return;
      }
      if (event.key !== 'Tab') return;
      const stops = focusable();
      if (stops.length === 0) return;
      const edge = event.shiftKey ? stops[0] : stops[stops.length - 1];
      if (document.activeElement !== edge) return;
      event.preventDefault();
      (event.shiftKey ? stops[stops.length - 1] : stops[0]).focus();
    };

    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      if (opener.current instanceof HTMLElement) opener.current.focus();
    };
  }, [focusable]);

  return (
    <Portal>
      <div
        className={`modal-backdrop${className ? ` ${className}` : ''}`}
        data-testid="modal-backdrop"
        onMouseDown={(event) => {
          if (!refuseClose && event.target === event.currentTarget) onClose();
        }}
      >
        <div
          ref={dialogRef}
          className="modal-container"
          role="dialog"
          aria-modal="true"
          aria-labelledby={titleId}
        >
          <div className="modal-header">
            <h2 id={titleId} className="modal-title">
              {title}
            </h2>
            <button
              type="button"
              className="modal-close"
              onClick={onClose}
              disabled={refuseClose}
              aria-label="close"
            >
              &times;
            </button>
          </div>
          <div className="modal-body">
            {error != null && (
              <p className="dialog-error" role="alert" data-testid="dialog-error">
                {error}
              </p>
            )}
            {children}
          </div>
        </div>
      </div>
    </Portal>
  );
}
