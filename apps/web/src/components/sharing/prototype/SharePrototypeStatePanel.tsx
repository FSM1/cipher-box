/** PROTOTYPE — throwaway. Stub-state drivers and a dump of the stub state. */
import {
  PROTO_PRESETS,
  protoExpiry,
  type ProtoDispatch,
  type ProtoState,
} from './SharePrototypeStore';

export function SharePrototypeStatePanel({
  state,
  dispatch,
}: {
  state: ProtoState;
  dispatch: ProtoDispatch;
}) {
  const act = (label: string, run: () => void) => (
    <button key={label} type="button" onClick={run}>
      {label}
    </button>
  );

  return (
    <details className="proto-state" open data-testid="proto-state-panel">
      <summary>prototype state</summary>
      <div className="proto-state-row">
        {PROTO_PRESETS.map((preset) =>
          act(preset.label, () => dispatch({ type: 'preset', key: preset.key }))
        )}
      </div>
      <div className="proto-state-row">
        {act('create link', () =>
          dispatch({ type: 'create-link', permission: 'read', lifetime: '7 days' })
        )}
        {act('simulate join', () => dispatch({ type: 'simulate-join' }))}
        {act('revoke person', () => dispatch({ type: 'ask-revoke', kind: 'person' }))}
        {act('revoke link', () => dispatch({ type: 'ask-revoke', kind: 'link' }))}
        {act('expire link', () => dispatch({ type: 'expire-link' }))}
        {act('reset', () => dispatch({ type: 'preset', key: 'empty' }))}
      </div>
      <pre className="proto-state-dump">
        {[
          `last:    ${state.last}`,
          `links:   ${
            state.links
              .map((link) => `${link.label}[${link.permission}, ${protoExpiry(link)}]`)
              .join(', ') || '-'
          }`,
          `people:  ${
            state.people
              .map(
                (person) =>
                  `${person.label}[${person.permission}, ${person.via}${person.converting ? ', converting' : ''}]`
              )
              .join(', ') || '-'
          }`,
          `shown:   ${state.fresh === null ? '-' : (state.links.find((link) => link.id === state.fresh?.linkId)?.label ?? '-')}`,
          `notice:  ${state.notice ?? '-'}`,
          `confirm: ${state.confirm === null ? '-' : `${state.confirm.kind} ${state.confirm.id}`}`,
        ].join('\n')}
      </pre>
    </details>
  );
}
