import { useCallback, useEffect, useId, useRef, type ReactNode } from 'react';
import { Portal } from './Portal';

const FOCUSABLE = 'button:not(:disabled), [href], input:not(:disabled), textarea, [tabindex="0"]';

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  /** Variant class on the backdrop, for wide dialogs like the previews. */
  className?: string;
  children: ReactNode;
}

/**
 * The one modal shell: a portalled backdrop, an Escape/backdrop close, and a
 * Tab cycle that cannot leave the dialog while it is open.
 */
export function Modal({ open, onClose, title, className, children }: ModalProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const opener = useRef<Element | null>(null);
  const titleId = useId();

  const focusable = useCallback(
    () => [...(dialogRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? [])],
    []
  );

  useEffect(() => {
    if (!open) return;
    opener.current = document.activeElement;
    // A field the dialog autofocused keeps it; otherwise focus enters at the top.
    if (!dialogRef.current?.contains(document.activeElement)) focusable()[0]?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
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
  }, [open, onClose, focusable]);

  if (!open) return null;

  return (
    <Portal>
      <div
        className={`modal-backdrop${className ? ` ${className}` : ''}`}
        data-testid="modal-backdrop"
        onMouseDown={(event) => {
          if (event.target === event.currentTarget) onClose();
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
            <button type="button" className="modal-close" onClick={onClose} aria-label="close">
              &times;
            </button>
          </div>
          <div className="modal-body">{children}</div>
        </div>
      </div>
    </Portal>
  );
}
