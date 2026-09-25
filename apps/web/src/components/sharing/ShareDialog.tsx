import { useEffect, useState, useSyncExternalStore } from 'react';
import type { Permission } from '@cipherbox/client';
import { useSharingActions, type SharingActions } from '../../hooks/useSharingActions';
import { accessLabel } from '../../sharing/inviteLink';
import { refusalLabel, refusalText } from '../../sharing/shareRefusals';
import {
  sharingFor,
  sharingStore,
  type ScopeSharing,
  type VerifiedContact,
} from '../../stores/sharing.store';
import type { ListingRow } from '../../vault/listing';
import { Modal } from '../ui/Modal';
import { ContactImportForm } from './ContactImportForm';
import { LinkSection } from './LinkSection';
import { PeopleTable } from './PeopleTable';

interface ShareDialogProps {
  /** The scope root being shared. */
  row: ListingRow;
  onClose: () => void;
}

/** Import is a step of this dialog, not a second one: one focus trap, one form. */
type Step = 'grants' | 'import';

/**
 * Who a folder is shared with, and the owner's changes to that set. The link
 * is the main path; the contact-code grant sits under "advanced" (ADR 0023
 * D7). The dialog issues one facade command per action and renders the
 * engine's own sharing read — it verifies nothing and remembers nothing of its
 * own.
 */
export function ShareDialog({ row, onClose }: ShareDialogProps) {
  const state = useSyncExternalStore(sharingStore.subscribe, sharingStore.getState);
  const actions = useSharingActions(row.id);
  const [step, setStep] = useState<Step>('grants');
  // Held until the dialog closes and no longer: unmounting is what forgets it.
  const [link, setLink] = useState<string | null>(null);

  // `null` is "no read reached this scope yet", which the table must not draw
  // as "shared with nobody".
  const scope = sharingFor(state, row.key);
  const busy = actions.busy !== null;

  const { open } = actions;
  useEffect(() => {
    void open();
  }, [open]);

  // A refusal belongs to the step that drew it; leaving the step retires it.
  const goTo = (next: Step) => {
    actions.clearError();
    setStep(next);
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
      error={actions.error === null ? null : refusalText(actions.error)}
      busy={busy}
      // A minted link is shown once, so only the deliberate exit discards it.
      dismissible={link === null}
    >
      {step === 'import' ? (
        <ContactImportForm
          busy={actions.busy === 'importContact'}
          ownContactCode={state.ownContactCode}
          onCancel={() => goTo('grants')}
          onConfirm={importContact}
        />
      ) : (
        <div className="dialog-content sharing-dialog" data-testid="share-dialog">
          <p className="dialog-label">
            {scope === null
              ? 'people with access'
              : `people with access · ${scope.grants.length + 1}`}
          </p>
          <PeopleTable grants={scope?.grants ?? null} actions={actions} busy={busy} />

          {scope !== null && (
            <LinkSection
              scope={scope}
              actions={actions}
              busy={busy}
              fresh={link}
              onMinted={setLink}
            />
          )}

          <details className="sharing-advanced" data-testid="share-advanced">
            <summary className="dialog-label">advanced: share by contact code</summary>
            <ContactGrant
              scope={scope}
              contacts={state.contacts}
              actions={actions}
              busy={busy}
              onImport={() => goTo('import')}
            />
          </details>

          <div className="dialog-actions">
            <button
              type="button"
              className="dialog-button"
              onClick={onClose}
              disabled={busy}
              data-testid="share-close"
            >
              {link === null ? 'done' : 'done — link saved'}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}

/** The contact-code grant: pick an imported contact and a permission. */
function ContactGrant({
  scope,
  contacts,
  actions,
  busy,
  onImport,
}: {
  scope: ScopeSharing | null;
  contacts: readonly VerifiedContact[];
  actions: SharingActions;
  busy: boolean;
  onImport: () => void;
}) {
  const [recipient, setRecipient] = useState('');
  const [permission, setPermission] = useState<Permission>('read');
  const granted = new Set((scope?.grants ?? []).map((entry) => entry.contact.key));
  const grantable = contacts.filter((contact) => !granted.has(contact.key));
  const chosen = grantable.find((contact) => contact.key === recipient) ?? null;
  // The engine's verdict on this target's standing, not a rule re-derived here.
  const grantRefusal = scope?.grantRefusal ?? null;

  const grant = () => {
    if (chosen === null) return;
    void actions.grant(chosen, permission).then((accepted) => {
      if (accepted) setRecipient('');
    });
  };

  return (
    <div className="dialog-content">
      {scope === null ? (
        <p className="sharing-note" data-testid="share-standing-unknown">
          {'// no read reached this folder — nothing can be granted until one does'}
        </p>
      ) : grantRefusal !== null ? (
        <p className="sharing-note" data-testid="share-no-grant" data-check={grantRefusal}>
          {`// ${refusalLabel(grantRefusal)}`}
        </p>
      ) : grantable.length === 0 ? (
        <p className="sharing-note" data-testid="share-no-contacts">
          {'// no contact left to grant here — import one'}
        </p>
      ) : (
        <div className="sharing-inline">
          <select
            className="dialog-input"
            aria-label="contact"
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
          <select
            className="dialog-input"
            aria-label="contact permission"
            value={permission}
            onChange={(event) => setPermission(event.target.value as Permission)}
            disabled={busy}
          >
            <option value="read">{`can ${accessLabel('read')}`}</option>
            <option value="write">{`can ${accessLabel('write')}`}</option>
          </select>
        </div>
      )}
      <div className="dialog-actions">
        <button
          type="button"
          className="dialog-button"
          onClick={onImport}
          disabled={busy}
          data-testid="share-import-contact"
        >
          import contact...
        </button>
        <button
          type="button"
          className="dialog-button dialog-button--primary"
          onClick={grant}
          disabled={busy || chosen === null || grantRefusal !== null || scope === null}
          data-testid="share-grant"
        >
          {actions.busy === 'grant' ? 'granting...' : 'grant'}
        </button>
      </div>
    </div>
  );
}
