import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import type { Permission } from '@cipherbox/client';
import { useSharingActions } from '../../hooks/useSharingActions';
import {
  expiryAt,
  expiryLabel,
  inviteUrl,
  LINK_LIFETIMES,
  type LinkLifetime,
} from '../../sharing/inviteLink';
import { sharingFor, sharingStore } from '../../stores/sharing.store';
import type { ListingRow } from '../../vault/listing';
import { CopyableValue } from '../file-browser/details/DetailsPrimitives';
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
  const [lifetime, setLifetime] = useState<LinkLifetime>('7 days');
  // Held until the dialog closes and no longer: unmounting is what forgets it.
  const [link, setLink] = useState<string | null>(null);
  // Closed before the dispatch rather than by a render: two activations in one
  // frame would mint two links and strand the first, a live capability nothing
  // can name again — and `busy` is itself the render-late value that misses it.
  const minting = useRef(false);

  // `null` is "no read reached this scope yet", which the list must not draw as
  // "granted to nobody" — the two differ to an owner deciding whether to grant
  // again.
  const scope = sharingFor(state, row.key);
  const rows = scope?.grants ?? null;
  const links = scope?.inviteLinks ?? null;
  const granted = new Set((rows ?? []).map((entry) => entry.contact.key));
  const grantable = state.contacts.filter((contact) => !granted.has(contact.key));
  const chosen = grantable.find((contact) => contact.key === recipient) ?? null;
  const busy = actions.busy !== null;

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

  const mintLink = () => {
    if (busy || minting.current) return;
    minting.current = true;
    void actions
      .createInviteLink(permission, expiryAt(lifetime, Date.now()))
      .then((fragment) => {
        if (fragment !== null) setLink(inviteUrl(fragment));
      })
      .finally(() => {
        minting.current = false;
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
      // A minted link is shown once, so only the deliberate exit discards it.
      dismissible={link === null}
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
          {rows === null ? (
            <p className="sharing-note" data-testid="share-grants-unavailable">
              {'// grants unavailable'}
            </p>
          ) : rows.length === 0 ? (
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
            </div>
          )}

          {/* One choice for both actions below: a grant and a minted link. */}
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

          <p className="dialog-label">invite link</p>
          {link !== null && (
            <div className="dialog-content" data-testid="invite-link">
              <CopyableValue value={link} label="invite link" />
              <p className="sharing-note" data-testid="invite-link-bearer">
                {'// whoever holds this link claims it — hand it over like a key'}
              </p>
            </div>
          )}

          {links === null ? (
            <p className="sharing-note" data-testid="share-links-unavailable">
              {'// link standing unavailable'}
            </p>
          ) : links.live ? (
            <div className="dialog-content" data-testid="share-live-link">
              <p className="sharing-note" data-testid="share-live-link-expiry">
                {`// a link stands here — ${expiryLabel(links.expiresAt, Date.now())}`}
              </p>
              <button
                type="button"
                className="dialog-button"
                onClick={() => void actions.convertInviteClaims()}
                disabled={busy}
                data-testid="share-convert-claims"
              >
                {actions.busy === 'convertInviteClaims' ? 'converting...' : 'convert claims'}
              </button>
              <button
                type="button"
                className="dialog-button dialog-button--danger"
                onClick={() => void actions.revokeInviteLink()}
                disabled={busy}
                data-testid="share-revoke-link"
              >
                {actions.busy === 'revokeInviteLink' ? 'revoking...' : 'revoke link'}
              </button>
            </div>
          ) : scope?.canMintShare === true ? (
            <div className="dialog-content">
              <label className="dialog-label" htmlFor="share-link-lifetime">
                link expires
              </label>
              <select
                id="share-link-lifetime"
                className="dialog-input"
                value={lifetime}
                onChange={(event) => setLifetime(event.target.value as LinkLifetime)}
                disabled={busy}
              >
                {Object.keys(LINK_LIFETIMES).map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
              <button
                type="button"
                className="dialog-button"
                onClick={mintLink}
                disabled={busy}
                data-testid="share-mint-link"
              >
                {actions.busy === 'createInviteLink' ? 'minting...' : 'mint invite link'}
              </button>
            </div>
          ) : (
            <p className="sharing-note" data-testid="share-no-mint">
              {'// this folder is already shared, so no further link can be minted here'}
            </p>
          )}

          {links !== null && links.spent > 0 && (
            <button
              type="button"
              className="dialog-button"
              onClick={() => void actions.pruneInviteLinks()}
              disabled={busy}
              data-testid="share-prune-links"
            >
              {actions.busy === 'pruneInviteLinks'
                ? 'pruning...'
                : `forget ${links.spent} spent link record${links.spent === 1 ? '' : 's'}`}
            </button>
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
              {link === null ? 'done' : 'done — link saved'}
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
