/**
 * PROTOTYPE — throwaway. A session-free host for the share-dialog prototype,
 * for a dev stack where sign-in cannot complete. The `/files` route hosts the
 * same dialog behind `?variant=` once signed in.
 */
import { useState } from 'react';
import { SharePrototypeDialog } from './SharePrototypeDialog';
import { SharePrototypeSwitcher } from './SharePrototypeSwitcher';
import { useSharePrototypeVariant } from './SharePrototypeVariant';

export function SharePrototypePage() {
  const variant = useSharePrototypeVariant() ?? 'A';
  const [open, setOpen] = useState(true);

  return (
    <div className="dialog-content" style={{ padding: 'var(--spacing-lg)' }}>
      <p className="dialog-label">prototype host · files / holiday photos</p>
      <ul className="sharing-list" style={{ maxWidth: 480 }}>
        <li className="sharing-row">
          <span className="sharing-key">holiday photos/</span>
          <button type="button" className="dialog-button" onClick={() => setOpen(true)}>
            share...
          </button>
        </li>
      </ul>
      {open && (
        <SharePrototypeDialog
          folderName="holiday photos"
          variant={variant}
          onClose={() => setOpen(false)}
        />
      )}
      <SharePrototypeSwitcher current={variant} />
    </div>
  );
}
