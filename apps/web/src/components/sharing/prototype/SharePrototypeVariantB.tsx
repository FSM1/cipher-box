/**
 * PROTOTYPE — throwaway. Variant B "people first": the people list is the
 * dialog; "add people" is a split action whose two paths open a small
 * sub-panel; live links shrink to chips under the list.
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

type Panel = 'none' | 'link' | 'contact';

export function SharePrototypeVariantB({
  state,
  dispatch,
}: {
  state: ProtoState;
  dispatch: ProtoDispatch;
}) {
  const [panel, setPanel] = useState<Panel>(state.fresh === null ? 'none' : 'link');
  const [menuOpen, setMenuOpen] = useState(false);
  const [permission, setPermission] = useState<ProtoPermission>('read');
  const [lifetime, setLifetime] = useState<ProtoLifetime>('7 days');
  const newest = state.notice === null ? null : state.people.find((person) => person.converting);

  return (
    <div className="dialog-content" data-testid="proto-variant-b">
      <div className="proto-b-head">
        <p className="dialog-label">{`people with access · ${state.people.length + 1}`}</p>
        <div className="proto-split">
          <button
            type="button"
            className="dialog-button dialog-button--primary"
            onClick={() => {
              setPanel(panel === 'link' ? 'none' : 'link');
              setMenuOpen(false);
            }}
          >
            + get a link
          </button>
          <button
            type="button"
            className="dialog-button dialog-button--primary proto-split-caret"
            aria-label="more ways to add people"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen(!menuOpen)}
          >
            ▾
          </button>
          {menuOpen && (
            <div className="proto-menu" role="menu">
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setPanel('link');
                  setMenuOpen(false);
                }}
              >
                get a link
              </button>
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setPanel('contact');
                  setMenuOpen(false);
                }}
              >
                advanced: by contact code
              </button>
            </div>
          )}
        </div>
      </div>

      {panel === 'link' && (
        <div className="proto-subpanel" data-testid="proto-b-link-panel">
          <p className="dialog-label">new invite link</p>
          <div className="proto-inline">
            <ProtoPermissionSelect
              id="proto-b-permission"
              value={permission}
              onChange={setPermission}
            />
            <ProtoLifetimeSelect id="proto-b-lifetime" value={lifetime} onChange={setLifetime} />
            <button
              type="button"
              className="dialog-button dialog-button--primary proto-nowrap"
              onClick={() => dispatch({ type: 'create-link', permission, lifetime })}
            >
              create
            </button>
          </div>
          <ProtoFreshLink state={state} dispatch={dispatch} />
          <button
            type="button"
            className="dialog-button proto-self-end"
            onClick={() => setPanel('none')}
          >
            close
          </button>
        </div>
      )}
      {panel === 'contact' && (
        <div className="proto-subpanel" data-testid="proto-b-contact-panel">
          <ProtoContactPath state={state} dispatch={dispatch} />
          <button
            type="button"
            className="dialog-button proto-self-end"
            onClick={() => setPanel('none')}
          >
            close
          </button>
        </div>
      )}

      {state.notice !== null && (
        <div className="proto-toast" role="status">
          {`${state.notice}`}
          <button
            type="button"
            className="details-copy"
            onClick={() => dispatch({ type: 'dismiss-notice' })}
          >
            ×
          </button>
        </div>
      )}

      {state.confirm !== null ? (
        <ProtoConfirmBox state={state} dispatch={dispatch} />
      ) : (
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
              <tr key={person.id} className={person === newest ? 'proto-people-new' : undefined}>
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
            ))}
            {state.people.length === 0 && (
              <tr>
                <td colSpan={5} className="proto-people-empty">
                  {'// only you have access. use "get a link" to invite someone.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}

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
    </div>
  );
}
