/** PROTOTYPE — throwaway. Stub-state drivers and a dump of the stub state. */
import {
  INVITE_PROTO_PRESETS,
  type InviteProtoDispatch,
  type InviteProtoState,
} from './InvitePrototypeStore';

export function InvitePrototypeStatePanel({
  state,
  dispatch,
}: {
  state: InviteProtoState;
  dispatch: InviteProtoDispatch;
}) {
  const act = (label: string, run: () => void) => (
    <button key={label} type="button" onClick={run}>
      {label}
    </button>
  );

  return (
    <details className="proto-inv-state" open data-testid="proto-state-panel">
      <summary>prototype state</summary>
      <div className="proto-inv-state-row">
        {INVITE_PROTO_PRESETS.map((preset) =>
          act(preset.label, () => dispatch({ type: 'preset', key: preset.key }))
        )}
      </div>
      <div className="proto-inv-state-row">
        {act('sign in', () => dispatch({ type: 'sign-in', method: 'google' }))}
        {act('join', () => dispatch({ type: 'join' }))}
        {act('expire', () => dispatch({ type: 'expire' }))}
        {act('revoke', () => dispatch({ type: 'revoke' }))}
        {act('mark already joined', () => dispatch({ type: 'mark-already-joined' }))}
        {act('toggle read/write', () => dispatch({ type: 'toggle-permission' }))}
        {act('reset', () => dispatch({ type: 'preset', key: 'arrival' }))}
      </div>
      <pre className="proto-inv-state-dump">
        {[
          `last:       ${state.last}`,
          `phase:      ${state.phase}${state.phase === 'preview' ? ` (C step: ${state.step})` : ''}`,
          `link:       ${state.link}, ${state.permission}`,
          `joined:     ${state.alreadyJoined ? 'already, on this account' : 'no'}`,
          `signed in:  ${state.identifier ?? '-'}`,
          `name field: ${state.phase === 'signed-out' ? '-' : JSON.stringify(state.name)}`,
          `persisted:  ${state.phase === 'joined' || state.phase === 'in-folder' ? 'bookmark + sealed claim' : 'nothing'}`,
        ].join('\n')}
      </pre>
    </details>
  );
}
