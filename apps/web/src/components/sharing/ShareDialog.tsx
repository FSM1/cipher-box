import { useState, useSyncExternalStore } from 'react';
import type { Permission } from '@cipherbox/client';
import type { SharingActions } from '../../hooks/useSharingActions';
import { grantsFor, sharingStore } from '../../sharing/sharingStore';
import type { ListingRow } from '../../vault/listing';
import { Modal } from '../ui/Modal';

interface ShareDialogProps {
  /** The scope root being shared. */
  row: ListingRow;
  actions: SharingActions;
  /** Opens the import step; a grant can only name an imported contact. */
  onImportContact: () => void;
  onClose: () => void;
}

/**
 * Who a folder is shared with, and the owner-only changes to that set: grant,
 * revoke, and the write→read downgrade. Every row is a command the engine
 * accepted; the dialog issues one command per action and renders the answer.
 */
export function ShareDialog({ row, actions, onImportContact, onClose }: ShareDialogProps) {
  const state = useSyncExternalStore(sharingStore.subscribe, sharingStore.getState);
  const [recipient, setRecipient] = useState('');
  const [permission, setPermission] = useState<Permission>('read');

  const rows = grantsFor(state, row.id);
  const granted = new Set(rows.map((grant) => grant.contact.key));
  const grantable = state.contacts.filter((contact) => !granted.has(contact.key));
  const chosen = grantable.find((contact) => contact.key === recipient) ?? null;
  const busy = actions.busy !== null;
  // The import step reports its own refusal, in its own dialog.
  const failure = actions.failure?.command === 'importContact' ? null : actions.failure;

  const grant = () => {
    if (chosen === null) return;
    void actions.grant(row.id, chosen, permission).then((accepted) => {
      if (accepted) setRecipient('');
    });
  };

  return (
    <Modal
      onClose={onClose}
      title={`share ${row.name}`}
      error={failure?.message ?? null}
      busy={busy}
    >
      <div className="dialog-content" data-testid="share-dialog">
        <p className="dialog-label">shared with</p>
        {rows.length === 0 ? (
          <p className="sharing-empty" data-testid="share-no-grants">
            {'// not shared with anyone'}
          </p>
        ) : (
          <ul className="sharing-list" data-testid="share-grant-list">
            {rows.map((entry) => (
              <li key={entry.contact.key} className="sharing-row" data-testid="share-grant-row">
                <span className="sharing-key">{entry.contact.key}</span>
                <span className="sharing-permission" data-testid="share-grant-permission">
                  {entry.permission}
                </span>
                {entry.permission === 'write' && (
                  <button
                    type="button"
                    className="dialog-button"
                    onClick={() => void actions.downgrade(row.id, entry.contact)}
                    disabled={busy}
                    data-testid="share-downgrade"
                  >
                    make read-only
                  </button>
                )}
                <button
                  type="button"
                  className="dialog-button dialog-button--danger"
                  onClick={() => void actions.revoke(row.id, entry.contact)}
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
          <p className="sharing-empty" data-testid="share-no-contacts">
            {'// no contact left to grant — import one to share with them'}
          </p>
        ) : (
          <div className="sharing-grant-form">
            <label className="sharing-field-label" htmlFor="share-recipient">
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
            <label className="sharing-field-label" htmlFor="share-permission">
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
            onClick={onImportContact}
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
    </Modal>
  );
}
