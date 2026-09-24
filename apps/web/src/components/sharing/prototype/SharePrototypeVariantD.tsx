/**
 * PROTOTYPE — throwaway. Variant D "people table + inline link": B's people
 * table on top, A's always-visible create-link row right under it, live
 * links as chips, and the contact-code path collapsed at the bottom.
 */
import { Fragment, useState } from 'react';
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

export function SharePrototypeVariantD({
  state,
  dispatch,
}: {
  state: ProtoState;
  dispatch: ProtoDispatch;
}) {
  const [permission, setPermission] = useState<ProtoPermission>('read');
  const [lifetime, setLifetime] = useState<ProtoLifetime>('7 days');
  const newest = state.notice === null ? null : state.people.find((person) => person.converting);
  const confirming = (kind: 'person' | 'link', id: string) =>
    state.confirm?.kind === kind && state.confirm.id === id;
  const linkConfirm = state.confirm?.kind === 'link';

  return (
    <div className="dialog-content" data-testid="proto-variant-d">
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

      <p className="dialog-label">{`people with access · ${state.people.length + 1}`}</p>
      <table className="proto-people">
        <thead>
          <tr>
            <th>who</th>
            <th>got in</th>
            <th>can</th>
            <th>since</th>
            <th />
          </tr>
        </thead>
        <tbody>
          <tr className="proto-people-owner">
            <td>you</td>
            <td>owner</td>
            <td>
              <span className="details-badge">owner</span>
            </td>
            <td />
            <td />
          </tr>
          {state.people.map((person) => (
            <Fragment key={person.id}>
              <tr className={person === newest ? 'proto-people-new' : undefined}>
                <td>
                  {person.label}
                  {person === newest && <span className="proto-new-badge">new</span>}
                </td>
                <td className="proto-dim">
                  {person.via === 'link'
                    ? `via ${protoLinkLabel(state, person.linkId)}`
                    : 'contact'}
                  {person.converting && ' · adding…'}
                </td>
                <td>
                  <span className={`details-badge proto-perm proto-perm--${person.permission}`}>
                    {person.permission === 'write' ? 'edit' : 'view'}
                  </span>
                </td>
                <td className="proto-dim">{protoAgo(person.joinedAt)}</td>
                <td>
                  <button
                    type="button"
                    className="dialog-button dialog-button--danger"
                    onClick={() => dispatch({ type: 'ask-revoke', kind: 'person', id: person.id })}
                  >
                    revoke
                  </button>
                </td>
              </tr>
              {confirming('person', person.id) && (
                <tr>
                  <td colSpan={5}>
                    <ProtoConfirmBox state={state} dispatch={dispatch} />
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
          {state.people.length === 0 && (
            <tr>
              <td colSpan={5} className="proto-people-empty">
                {'// only you have access. create a link below to invite someone.'}
              </td>
            </tr>
          )}
        </tbody>
      </table>

      <p className="dialog-label">invite with a link</p>
      <div className="proto-inline">
        <ProtoPermissionSelect
          id="proto-d-permission"
          value={permission}
          onChange={setPermission}
        />
        <ProtoLifetimeSelect id="proto-d-lifetime" value={lifetime} onChange={setLifetime} />
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

      <div className="proto-chips">
        <span className="dialog-label">links</span>
        {state.links.length === 0 && <span className="sharing-note">{'// none'}</span>}
        {state.links.map((link) => (
          <span
            key={link.id}
            className={`proto-chip${link.expired ? ' proto-chip--expired' : ''}${
              link.permission === 'write' ? ' proto-chip--write' : ''
            }`}
            title={`${link.label}: ${link.permission}, ${protoExpiry(link)}`}
          >
            {`${link.label} · ${link.permission === 'write' ? 'edit' : 'view'} · ${protoExpiry(link)}`}
            <button
              type="button"
              aria-label={`revoke ${link.label}`}
              onClick={() => dispatch({ type: 'ask-revoke', kind: 'link', id: link.id })}
            >
              ×
            </button>
          </span>
        ))}
      </div>
      {linkConfirm && <ProtoConfirmBox state={state} dispatch={dispatch} />}

      <details className="proto-advanced">
        <summary className="dialog-label">advanced: share by contact code</summary>
        <ProtoContactPath state={state} dispatch={dispatch} />
      </details>
    </div>
  );
}
