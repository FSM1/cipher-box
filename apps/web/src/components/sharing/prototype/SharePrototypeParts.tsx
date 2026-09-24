/** PROTOTYPE — throwaway. Small pieces the variants place differently. */
import { useState, type ReactNode } from 'react';
import {
  PROTO_LIFETIMES,
  protoRevokeImpact,
  type ProtoDispatch,
  type ProtoLifetime,
  type ProtoPermission,
  type ProtoState,
} from './SharePrototypeStore';

export function ProtoConfirmBox({
  state,
  dispatch,
}: {
  state: ProtoState;
  dispatch: ProtoDispatch;
}) {
  if (state.confirm === null) return null;
  const impact = protoRevokeImpact(state, state.confirm);
  return (
    <div className="proto-confirm" role="alertdialog" data-testid="proto-confirm">
      <p className="proto-confirm-title">{impact.title}</p>
      {impact.lines.map((line) => (
        <p key={line} className="sharing-note">
          {`// ${line}`}
        </p>
      ))}
      <div className="dialog-actions">
        <button
          type="button"
          className="dialog-button"
          onClick={() => dispatch({ type: 'cancel-revoke' })}
        >
          keep
        </button>
        <button
          type="button"
          className="dialog-button dialog-button--danger"
          onClick={() => dispatch({ type: 'confirm-revoke' })}
        >
          revoke
        </button>
      </div>
    </div>
  );
}

export function ProtoPermissionSelect({
  id,
  value,
  onChange,
}: {
  id: string;
  value: ProtoPermission;
  onChange: (next: ProtoPermission) => void;
}) {
  return (
    <select
      id={id}
      className="dialog-input"
      value={value}
      onChange={(event) => onChange(event.target.value as ProtoPermission)}
    >
      <option value="read">can view</option>
      <option value="write">can edit</option>
    </select>
  );
}

export function ProtoLifetimeSelect({
  id,
  value,
  onChange,
}: {
  id: string;
  value: ProtoLifetime;
  onChange: (next: ProtoLifetime) => void;
}) {
  return (
    <select
      id={id}
      className="dialog-input"
      value={value}
      onChange={(event) => onChange(event.target.value as ProtoLifetime)}
    >
      {PROTO_LIFETIMES.map((lifetime) => (
        <option key={lifetime} value={lifetime}>
          {lifetime === 'never' ? 'never expires' : `expires in ${lifetime}`}
        </option>
      ))}
    </select>
  );
}

/** The contact-code path: own code, import field, grant to a contact. */
export function ProtoContactPath({
  state,
  dispatch,
}: {
  state: ProtoState;
  dispatch: ProtoDispatch;
}) {
  const [code, setCode] = useState('');
  const [contact, setContact] = useState('');
  const [permission, setPermission] = useState<ProtoPermission>('read');
  const chosen = state.contacts.find((entry) => entry.id === contact) ?? null;

  return (
    <div className="dialog-content" data-testid="proto-contact-path">
      <p className="dialog-label">your contact code</p>
      <div className="proto-code">
        <span className="details-copyable-text">{state.ownContactCode}</span>
        <button type="button" className="details-copy">
          copy
        </button>
      </div>
      <p className="sharing-note">{'// send this to them — an exchange needs both codes'}</p>

      <label className="dialog-label" htmlFor="proto-import-code">
        their contact code
      </label>
      <textarea
        id="proto-import-code"
        className="dialog-input sharing-code-field proto-code-field"
        value={code}
        onChange={(event) => setCode(event.target.value)}
        placeholder="paste their code"
        spellCheck={false}
      />
      <div className="dialog-actions">
        <button
          type="button"
          className="dialog-button"
          disabled={code.trim() === ''}
          onClick={() => {
            dispatch({ type: 'import-contact', code });
            setCode('');
          }}
        >
          import
        </button>
      </div>

      <p className="dialog-label">grant to a contact</p>
      {state.contacts.length === 0 ? (
        <p className="sharing-note">{'// no contact left to grant here — import one'}</p>
      ) : (
        <div className="proto-inline">
          <select
            className="dialog-input"
            value={contact}
            onChange={(event) => setContact(event.target.value)}
            aria-label="contact"
          >
            <option value="">select a contact</option>
            {state.contacts.map((entry) => (
              <option key={entry.id} value={entry.id}>
                {entry.label}
              </option>
            ))}
          </select>
          <ProtoPermissionSelect
            id="proto-contact-permission"
            value={permission}
            onChange={setPermission}
          />
          <button
            type="button"
            className="dialog-button dialog-button--primary"
            disabled={chosen === null}
            onClick={() => {
              if (chosen === null) return;
              dispatch({ type: 'grant-contact', contactId: chosen.id, permission });
              setContact('');
            }}
          >
            grant
          </button>
        </div>
      )}
    </div>
  );
}

export function ProtoFreshLink({
  state,
  dispatch,
  extra,
}: {
  state: ProtoState;
  dispatch: ProtoDispatch;
  extra?: ReactNode;
}) {
  if (state.fresh === null) return null;
  const link = state.links.find((entry) => entry.id === state.fresh?.linkId);
  return (
    <div className="proto-fresh" data-testid="proto-fresh-link">
      <div className="proto-code">
        <span className="details-copyable-text">{state.fresh.url}</span>
        <button type="button" className="details-copy">
          copy
        </button>
      </div>
      {extra}
      <p className="sharing-note proto-warn">
        {`// shown once — copy it now. anyone who opens it and presses join gets ${
          link?.permission === 'write' ? 'EDIT' : 'view'
        } access, with no click from you.`}
      </p>
      <div className="dialog-actions">
        <button
          type="button"
          className="dialog-button"
          onClick={() => dispatch({ type: 'hide-fresh' })}
        >
          i copied it — hide
        </button>
      </div>
    </div>
  );
}
