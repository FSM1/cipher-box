import { ReactNode, useEffect, useRef, useCallback } from 'react';
import { Portal } from './Portal';
import '../../styles/modal.css';

type ModalProps = {
  open: boolean;
  onClose?: () => void;
  children: ReactNode;
  title?: string;
  /** Optional class applied to the backdrop for variant styling */
  className?: string;
};

/**
 * Reusable modal dialog component.
 * Features:
 * - Renders in portal outside component tree
 * - Backdrop with optional click-to-close
 * - Close button (X) when onClose provided
 * - Escape key closes when onClose provided
 * - Focus trap: prevents tab from leaving modal
 * - Accessible: aria-modal, role="dialog"
 */
export function Modal({ open, onClose, children, title, className }: ModalProps) {
  const modalRef = useRef<HTMLDivElement>(null);
  const previousActiveElement = useRef<Element | null>(null);

  // Handle escape key
  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      if (event.key === 'Escape' && onClose) {
        onClose();
      }
    },
    [onClose]
  );

  // Focus trap: keep focus within modal
  const handleFocusTrap = useCallback((event: KeyboardEvent) => {
    if (event.key !== 'Tab' || !modalRef.current) return;

    const focusableElements = modalRef.current.querySelectorAll<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );

    if (focusableElements.length === 0) return;

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];

    if (event.shiftKey) {
      // Shift+Tab: if on first element, move to last
      if (document.activeElement === firstElement) {
        event.preventDefault();
        lastElement.focus();
      }
    } else {
      // Tab: if on last element, move to first
      if (document.activeElement === lastElement) {
        event.preventDefault();
        firstElement.focus();
      }
    }
  }, []);

  useEffect(() => {
    if (!open) return;

    // Store currently focused element
    previousActiveElement.current = document.activeElement;

    // Focus first focusable element in modal
    const focusableElements = modalRef.current?.querySelectorAll<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    if (focusableElements && focusableElements.length > 0) {
      focusableElements[0].focus();
    }

    // Add event listeners
    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('keydown', handleFocusTrap);

    // Cleanup
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('keydown', handleFocusTrap);
      // Restore focus on close
      if (previousActiveElement.current instanceof HTMLElement) {
        previousActiveElement.current.focus();
      }
    };
  }, [open, handleKeyDown, handleFocusTrap]);

  if (!open) {
    return null;
  }

  const handleBackdropClick = (event: React.MouseEvent) => {
    // Only close if clicking the backdrop itself, not the modal content
    if (event.target === event.currentTarget && onClose) {
      onClose();
    }
  };

  return (
    <Portal>
      <div
        className={`modal-backdrop${className ? ` ${className}` : ''}`}
        onClick={handleBackdropClick}
      >
        <div
          ref={modalRef}
          className="modal-container"
          role="dialog"
          aria-modal="true"
          aria-labelledby={title ? 'modal-title' : undefined}
        >
          {(title || onClose) && (
            <div className="modal-header">
              {title && (
                <h2 id="modal-title" className="modal-title">
                  {title}
                </h2>
              )}
              {onClose && (
                <button
                  type="button"
                  className="modal-close"
                  onClick={onClose}
                  aria-label="Close modal"
                >
                  &times;
                </button>
              )}
            </div>
          )}
          <div className="modal-body">{children}</div>
        </div>
      </div>
    </Portal>
  );
}
