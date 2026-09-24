/**
 * PROTOTYPE — throwaway. Variant C "steps": a three-step stepper (choose,
 * link, who joined) on the main tab; the contact-code path is its own tab.
 * Step 3 reads as a timeline, not a list of rows.
 */
import { useState } from 'react';
import { ProtoConfirmBox, ProtoContactPath, ProtoFreshLink } from './SharePrototypeParts';
import {
  PROTO_LIFETIMES,
  protoAgo,
  protoExpiry,
  protoLinkLabel,
  type ProtoDispatch,
  type ProtoLifetime,
  type ProtoLink,
  type ProtoPerson,
  type ProtoPermission,
  type ProtoState,
} from './SharePrototypeStore';

type Tab = 'link' | 'advanced';
type Step = 1 | 2 | 3;

type Event =
  | { at: number; kind: 'created' | 'expired'; link: ProtoLink }
  | { at: number; kind: 'joined' | 'granted'; person: ProtoPerson };

function timeline(state: ProtoState): Event[] {
  const events: Event[] = [];
  for (const link of state.links) {
    events.push({ at: link.createdAt, kind: 'created', link });
    if (link.expired) events.push({ at: link.expiresAt ?? Date.now(), kind: 'expired', link });
  }
  for (const person of state.people) {
    events.push({
      at: person.joinedAt,
      kind: person.via === 'link' ? 'joined' : 'granted',
      person,
    });
  }
  return events.sort((a, b) => b.at - a.at);
}

const STEPS: { step: Step; label: string }[] = [
  { step: 1, label: 'choose' },
  { step: 2, label: 'send the link' },
  { step: 3, label: 'who joined' },
];

export function SharePrototypeVariantC({
  state,
  dispatch,
}: {
  state: ProtoState;
  dispatch: ProtoDispatch;
}) {
  const [tab, setTab] = useState<Tab>('link');
  const [step, setStep] = useState<Step>(
    state.fresh !== null ? 2 : state.links.length + state.people.length > 0 ? 3 : 1
  );
  const [permission, setPermission] = useState<ProtoPermission>('read');
  const [lifetime, setLifetime] = useState<ProtoLifetime>('7 days');
  const events = timeline(state);
  const liveLinks = state.links.filter((link) => !link.expired).length;

  return (
    <div className="dialog-content" data-testid="proto-variant-c">
      <div className="proto-tabs" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'link'}
          onClick={() => setTab('link')}
        >
          invite link
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'advanced'}
          onClick={() => setTab('advanced')}
        >
          advanced
        </button>
      </div>

      {tab === 'advanced' ? (
        <ProtoContactPath state={state} dispatch={dispatch} />
      ) : (
        <>
          <ol className="proto-stepper">
            {STEPS.map((entry) => (
              <li key={entry.step}>
                <button
                  type="button"
                  className={step === entry.step ? 'proto-step proto-step--on' : 'proto-step'}
                  onClick={() => setStep(entry.step)}
                  disabled={entry.step === 2 && state.fresh === null}
                >
                  <span className="proto-step-n">{entry.step}</span>
                  {entry.label}
                  {entry.step === 3 && ` (${state.people.length})`}
                </button>
              </li>
            ))}
          </ol>

          {state.notice !== null && step !== 3 && (
            <button
              type="button"
              className="proto-notice proto-notice--button"
              onClick={() => setStep(3)}
            >
              {`// ${state.notice} — see who joined →`}
            </button>
          )}

          {step === 1 && (
            <div className="dialog-content">
              <p className="dialog-label">what can they do</p>
              <div className="proto-choice">
                {(['read', 'write'] as const).map((option) => (
                  <label key={option} className="proto-choice-row">
                    <input
                      type="radio"
                      name="proto-c-permission"
                      checked={permission === option}
                      onChange={() => setPermission(option)}
                    />
                    <span>
                      <strong>{option === 'read' ? 'view' : 'edit'}</strong>
                      <span className="proto-dim">
                        {option === 'read'
                          ? ' — open and download files'
                          : ' — also add, rename and delete files'}
                      </span>
                    </span>
                  </label>
                ))}
              </div>
              <p className="dialog-label">how long can the link be used</p>
              <div className="proto-segments">
                {PROTO_LIFETIMES.map((option) => (
                  <button
                    key={option}
                    type="button"
                    aria-pressed={lifetime === option}
                    onClick={() => setLifetime(option)}
                  >
                    {option}
                  </button>
                ))}
              </div>
              <div className="dialog-actions">
                <button
                  type="button"
                  className="dialog-button dialog-button--primary"
                  onClick={() => {
                    dispatch({ type: 'create-link', permission, lifetime });
                    setStep(2);
                  }}
                >
                  create link →
                </button>
              </div>
            </div>
          )}

          {step === 2 &&
            (state.fresh === null ? (
              <p className="sharing-note">
                {'// the link was shown once and is hidden now. create a new one in step 1.'}
              </p>
            ) : (
              <div className="dialog-content">
                <ProtoFreshLink
                  state={state}
                  dispatch={(action) => {
                    dispatch(action);
                    if (action.type === 'hide-fresh') setStep(3);
                  }}
                  extra={
                    <div className="proto-qr" aria-label="QR code placeholder">
                      QR
                    </div>
                  }
                />
              </div>
            ))}

          {step === 3 && (
            <div className="dialog-content">
              <p className="sharing-note">
                {`// ${state.people.length} ${state.people.length === 1 ? 'person' : 'people'} · ${liveLinks} live link${liveLinks === 1 ? '' : 's'}`}
              </p>
              {events.length === 0 ? (
                <p className="sharing-note">{'// nothing yet — start at step 1'}</p>
              ) : (
                <ol className="proto-timeline">
                  {events.map((event) => {
                    const key = `${event.kind}-${'link' in event ? event.link.id : event.person.id}`;
                    const confirmHere =
                      state.confirm !== null &&
                      (('person' in event &&
                        state.confirm.kind === 'person' &&
                        state.confirm.id === event.person.id) ||
                        ('link' in event &&
                          event.kind === 'created' &&
                          state.confirm.kind === 'link' &&
                          state.confirm.id === event.link.id));
                    return (
                      <li key={key} className={`proto-event proto-event--${event.kind}`}>
                        <span className="proto-event-when">{protoAgo(event.at)}</span>
                        <div className="proto-event-body">
                          <EventText state={state} event={event} />
                          {event.kind !== 'expired' && !('link' in event && event.link.expired) && (
                            <button
                              type="button"
                              className="details-copy proto-event-revoke"
                              onClick={() =>
                                dispatch(
                                  'person' in event
                                    ? { type: 'ask-revoke', kind: 'person', id: event.person.id }
                                    : { type: 'ask-revoke', kind: 'link', id: event.link.id }
                                )
                              }
                            >
                              revoke
                            </button>
                          )}
                          {confirmHere && <ProtoConfirmBox state={state} dispatch={dispatch} />}
                        </div>
                      </li>
                    );
                  })}
                </ol>
              )}
              <div className="dialog-actions">
                <button type="button" className="dialog-button" onClick={() => setStep(1)}>
                  + another link
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function EventText({ state, event }: { state: ProtoState; event: Event }) {
  switch (event.kind) {
    case 'created':
      return (
        <span>
          {`${event.link.label} created · `}
          <span className="details-badge">{event.link.permission}</span>
          <span className="proto-dim">{` · ${protoExpiry(event.link)}`}</span>
        </span>
      );
    case 'expired':
      return (
        <span className="proto-dim">{`${event.link.label} expired — nobody new can join with it`}</span>
      );
    case 'joined':
      return (
        <span>
          {`${event.person.label} joined via ${protoLinkLabel(state, event.person.linkId)} · `}
          <span className="details-badge">{event.person.permission}</span>
          {event.person.converting && <span className="proto-dim">{' · adding…'}</span>}
        </span>
      );
    case 'granted':
      return (
        <span>
          {`${event.person.label} added by contact code · `}
          <span className="details-badge">{event.person.permission}</span>
        </span>
      );
  }
}
