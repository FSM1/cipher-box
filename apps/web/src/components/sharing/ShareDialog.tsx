import { useEffect, useState, useSyncExternalStore } from 'react';
import type { Permission } from '@cipherbox/client';
import { useSharingActions } from '../../hooks/useSharingActions';
import { grantsFor, sharingStore } from '../../stores/sharing.store';
import type { ListingRow } from '../../vault/listing';
import { Modal } from '../ui/Modal';
import { ContactImportForm } from './ContactImportForm';

interface ShareDialogProps {
  /** The scope root being shared. */
  row: ListingRow;
  onClose: () => void;
}

/** Import is a step of this dialog, not a second one: one focus trap, one form. */
type Step = 'grants' | 'import';

/**
 * Who a folder is shared with, and the owner-only changes to that set: grant,
 * revoke, and the write→read downgrade. The dialog issues one facade command
 * per action and renders the engine's own sharing read — it verifies nothing
 * and remembers nothing of its own.
 */
export function ShareDialog({ row, onClose }: ShareDialogProps) {
  const state = useSyncExternalStore(sharingStore.subscribe, sharingStore.getState);
  const actions = useSharingActions(row.id);
  const [step, setStep] = useState<Step>('grants');
  const [recipient, setRecipient] = useState('');
  const [permission, setPermission] = useState<Permission>('read');

  const rows = grantsFor(state, row.key);
  const granted = new Set(rows.map((entry) => entry.contact.key));
  const grantable = state.contacts.filter((contact) => !granted.has(contact.key));
  const chosen = grantable.find((contact) => contact.key === recipient) ?? null;
  const busy = actions.busy !== null;

  // `reload` changes identity only when the scope or the engine client does, so
  // this reads once per scope and again once the engine is there to answer.
  const { reload } = actions;
  useEffect(() => {
    void reload();
  }, [reload]);

  // A refusal belongs to the step that drew it; leaving the step retires it.
  const goTo = (next: Step) => {
    actions.clearError();
    setStep(next);
  };

  const grant = () => {
    if (chosen === null) return;
    void actions.grant(chosen, permission).then((accepted) => {
      if (accepted) setRecipient('');
    });
  };

  const importContact = (code: Uint8Array) => {
    void actions.importContact(code).then((verified) => {
      if (verified) setStep('grants');
    });
  };

  return (
    <Modal
      onClose={onClose}
      title={step === 'import' ? 'import contact' : `share ${row.name}`}
      error={actions.error}
      busy={busy}
    >
      {step === 'import' ? (
        <ContactImportForm
          busy={actions.busy === 'importContact'}
          onCancel={() => goTo('grants')}
          onConfirm={importContact}
        />
      ) : (
        <div className="dialog-content" data-testid="share-dialog">
          <p className="dialog-label">shared with</p>
          {rows.length === 0 ? (
            <p className="sharing-note" data-testid="share-no-grants">
              {'// nothing granted here'}
            </p>
          ) : (
            <ul className="sharing-list" data-testid="share-grant-list">
              {rows.map((entry) => (
                <li key={entry.contact.key} className="sharing-row" data-testid="share-grant-row">
                  <span className="sharing-key">{entry.contact.key}</span>
                  <span className="details-badge" data-testid="share-grant-permission">
                    {entry.permission}
                  </span>
                  {entry.permission === 'write' && (
                    <button
                      type="button"
                      className="dialog-button"
                      onClick={() => void actions.downgrade(entry.contact)}
                      disabled={busy}
                      data-testid="share-downgrade"
                    >
                      make read-only
                    </button>
                  )}
                  <button
                    type="button"
                    className="dialog-button dialog-button--danger"
                    onClick={() => void actions.revoke(entry.contact)}
                    disabled={busy}
                    data-testid="share-revoke"
                  >
                    revoke
                  </button>
                </li>
              ))}
            </ul>
          )}

          <p className="dialog-label">grant access</p>
          {grantable.length === 0 ? (
            <p className="sharing-note" data-testid="share-no-contacts">
              {'// no contact left to grant here — import one'}
            </p>
          ) : (
            <div className="dialog-content">
              <label className="dialog-label" htmlFor="share-recipient">
                contact
              </label>
              <select
                id="share-recipient"
                className="dialog-input"
                value={recipient}
                onChange={(event) => setRecipient(event.target.value)}
                disabled={busy}
              >
                <option value="">select a contact</option>
                {grantable.map((contact) => (
                  <option key={contact.key} value={contact.key}>
                    {contact.key}
                  </option>
                ))}
              </select>
              <label className="dialog-label" htmlFor="share-permission">
                permission
              </label>
              <select
                id="share-permission"
                className="dialog-input"
                value={permission}
                onChange={(event) => setPermission(event.target.value as Permission)}
                disabled={busy}
              >
                <option value="read">read</option>
                <option value="write">write</option>
              </select>
            </div>
          )}

          <div className="dialog-actions">
            <button
              type="button"
              className="dialog-button"
              onClick={() => goTo('import')}
              disabled={busy}
              data-testid="share-import-contact"
            >
              import contact...
            </button>
            <button
              type="button"
              className="dialog-button"
              onClick={onClose}
              disabled={busy}
              data-testid="share-close"
            >
              done
            </button>
            <button
              type="button"
              className="dialog-button dialog-button--primary"
              onClick={grant}
              disabled={busy || chosen === null}
              data-testid="share-grant"
            >
              {actions.busy === 'grant' ? 'granting...' : 'grant'}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}
