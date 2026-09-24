/**
 * PROTOTYPE — throwaway. Variant C: three steps. 1 signed in, 2 look inside
 * (the preview alone), 3 join (name field, "join", a one-line summary).
 */
import {
  InviteProtoCounts,
  InviteProtoHeader,
  InviteProtoJoinButton,
  InviteProtoNameField,
  InviteProtoPlainList,
} from './InvitePrototypeParts';
import {
  INVITE_PROTO_FOLDER,
  protoCounts,
  protoPermissionLabel,
  type InviteProtoDispatch,
  type InviteProtoState,
} from './InvitePrototypeStore';

export function InvitePrototypeVariantC({
  state,
  dispatch,
}: {
  state: InviteProtoState;
  dispatch: InviteProtoDispatch;
}) {
  const steps = [
    { n: 1, label: `signed in as ${state.identifier ?? '-'}`, done: true, on: false },
    { n: 2, label: 'look inside', done: state.step === 'join', on: state.step === 'look' },
    { n: 3, label: 'join', done: false, on: state.step === 'join' },
  ];

  return (
    <div className="login-panel proto-inv-panel proto-inv-steps" data-testid="proto-invite-c">
      <h1>CipherBox</h1>
      <p className="tagline">invite link</p>
      <ol className="proto-inv-stepper">
        {steps.map((step) => (
          <li
            key={step.n}
            className={`proto-inv-step${step.on ? ' proto-inv-step--on' : ''}${step.done ? ' proto-inv-step--done' : ''}`}
            aria-current={step.on ? 'step' : undefined}
          >
            <span className="proto-inv-step-n">{step.done ? '✓' : step.n}</span>
            <span className="proto-inv-step-label">{step.label}</span>
          </li>
        ))}
      </ol>

      {state.step === 'look' ? (
        <div className="proto-inv-step-body">
          <InviteProtoHeader permission={state.permission} />
          <InviteProtoPlainList />
          <InviteProtoCounts />
          <button
            type="button"
            className="terminal-btn terminal-btn--filled proto-inv-self-end"
            onClick={() => dispatch({ type: 'next' })}
          >
            next
          </button>
        </div>
      ) : (
        <div className="proto-inv-step-body">
          <p className="proto-inv-summary">
            you get {INVITE_PROTO_FOLDER.name} from {INVITE_PROTO_FOLDER.owner},{' '}
            {protoPermissionLabel(state.permission)}: {protoCounts(INVITE_PROTO_FOLDER.entries)}.
          </p>
          <InviteProtoNameField state={state} dispatch={dispatch} />
          <div className="proto-inv-row">
            <button
              type="button"
              className="terminal-btn"
              onClick={() => dispatch({ type: 'back' })}
            >
              back
            </button>
            <InviteProtoJoinButton dispatch={dispatch} />
          </div>
        </div>
      )}
    </div>
  );
}
