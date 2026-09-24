/**
 * PROTOTYPE — throwaway. Variant A "link first": one primary create action
 * with permission and lifetime inline, the people and links as plain rows
 * below, and the contact-code path collapsed at the bottom.
 */
import { useState } from 'react';
import {
  ProtoConfirmBox,
  ProtoContactPath,
  ProtoFreshLink,
  ProtoLifetimeSelect,
  ProtoPermissionSelect,
} from './SharePrototypeParts';
import {
  protoAgo,
  protoExpiry,
  protoLinkLabel,
  type ProtoDispatch,
  type ProtoLifetime,
  type ProtoPermission,
  type ProtoState,
} from './SharePrototypeStore';

export function SharePrototypeVariantA({
  state,
  dispatch,
}: {
  state: ProtoState;
  dispatch: ProtoDispatch;
}) {
  const [permission, setPermission] = useState<ProtoPermission>('read');
  const [lifetime, setLifetime] = useState<ProtoLifetime>('7 days');
  const confirming = (kind: 'person' | 'link', id: string) =>
    state.confirm?.kind === kind && state.confirm.id === id;

  return (
    <div className="dialog-content" data-testid="proto-variant-a">
      {state.notice !== null && (
        <div className="proto-notice">
          <span>{`// ${state.notice} — access is being added in the background`}</span>
          <button
            type="button"
            className="details-copy"
            onClick={() => dispatch({ type: 'dismiss-notice' })}
          >
            ok
          </button>
        </div>
      )}

      <p className="dialog-label">invite with a link</p>
      <div className="proto-inline">
        <ProtoPermissionSelect
          id="proto-a-permission"
          value={permission}
          onChange={setPermission}
        />
        <ProtoLifetimeSelect id="proto-a-lifetime" value={lifetime} onChange={setLifetime} />
        <button
          type="button"
          className="dialog-button dialog-button--primary proto-nowrap"
          onClick={() => dispatch({ type: 'create-link', permission, lifetime })}
        >
          create link
        </button>
      </div>
      {permission === 'write' && (
        <p className="sharing-note proto-warn">
          {'// a write link lets anyone who holds it change and delete files here'}
        </p>
      )}
      <ProtoFreshLink state={state} dispatch={dispatch} />

      <p className="dialog-label">{`people with access (${state.people.length})`}</p>
      {state.people.length === 0 ? (
        <p className="sharing-note">{'// only you — create a link and send it'}</p>
      ) : (
        <ul className="sharing-list">
          {state.people.map((person) => (
            <li key={person.id} className="proto-row-wrap">
              <div className="sharing-row">
                <span className="sharing-key">
                  {person.label}
                  <span className="proto-dim">
                    {` · ${person.via === 'link' ? `via ${protoLinkLabel(state, person.linkId)}` : 'contact'} · ${protoAgo(person.joinedAt)}`}
                  </span>
                  {person.converting && <span className="proto-dim">{' · adding…'}</span>}
                </span>
                <span className="details-badge">{person.permission}</span>
                <button
                  type="button"
                  className="dialog-button dialog-button--danger"
                  onClick={() => dispatch({ type: 'ask-revoke', kind: 'person', id: person.id })}
                >
                  revoke
                </button>
              </div>
              {confirming('person', person.id) && (
                <ProtoConfirmBox state={state} dispatch={dispatch} />
              )}
            </li>
          ))}
        </ul>
      )}

      <p className="dialog-label">{`links (${state.links.length})`}</p>
      {state.links.length === 0 ? (
        <p className="sharing-note">{'// no link'}</p>
      ) : (
        <ul className="sharing-list">
          {state.links.map((link) => {
            const joined = state.people.filter((person) => person.linkId === link.id).length;
            return (
              <li key={link.id} className="proto-row-wrap">
                <div className={`sharing-row${link.expired ? ' proto-expired' : ''}`}>
                  <span className="sharing-key">
                    {link.label}
                    <span className="proto-dim">{` · ${protoExpiry(link)} · ${joined} joined`}</span>
                  </span>
                  <span className="details-badge">{link.permission}</span>
                  <button
                    type="button"
                    className="dialog-button dialog-button--danger"
                    onClick={() => dispatch({ type: 'ask-revoke', kind: 'link', id: link.id })}
                  >
                    {link.expired ? 'remove' : 'revoke'}
                  </button>
                </div>
                {confirming('link', link.id) && (
                  <ProtoConfirmBox state={state} dispatch={dispatch} />
                )}
              </li>
            );
          })}
        </ul>
      )}

      <details className="proto-advanced">
        <summary className="dialog-label">advanced: share by contact code</summary>
        <ProtoContactPath state={state} dispatch={dispatch} />
      </details>
    </div>
  );
}
