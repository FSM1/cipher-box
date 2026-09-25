import type { ReactNode } from 'react';

interface ConfirmProps {
  title: string;
  /** The notes and any control the confirmation carries, between title and buttons. */
  children: ReactNode;
  confirmLabel: string;
  busy: boolean;
  onKeep: () => void;
  onConfirm: () => void;
  /** The prefix of the `-prompt`, `-cancel` and `-confirm` test ids. */
  testId: string;
}

/** An inline confirmation of a destructive sharing action: keep, or go ahead. */
export function Confirm({
  title,
  children,
  confirmLabel,
  busy,
  onKeep,
  onConfirm,
  testId,
}: ConfirmProps) {
  return (
    <div className="sharing-confirm" role="alertdialog" data-testid={`${testId}-prompt`}>
      <p className="sharing-confirm-title">{title}</p>
      {children}
      <div className="dialog-actions">
        <button
          type="button"
          className="dialog-button"
          onClick={onKeep}
          disabled={busy}
          data-testid={`${testId}-cancel`}
        >
          keep
        </button>
        <button
          type="button"
          className="dialog-button dialog-button--danger"
          onClick={onConfirm}
          disabled={busy}
          data-testid={`${testId}-confirm`}
        >
          {confirmLabel}
        </button>
      </div>
    </div>
  );
}
