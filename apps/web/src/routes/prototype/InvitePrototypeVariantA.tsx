/** PROTOTYPE — throwaway. Variant A: one stacked card, everything on one screen. */
import {
  InviteProtoCounts,
  InviteProtoHeader,
  InviteProtoJoinButton,
  InviteProtoNameField,
  InviteProtoPlainList,
  InviteProtoSignedInAs,
} from './InvitePrototypeParts';
import type { InviteProtoDispatch, InviteProtoState } from './InvitePrototypeStore';

export function InvitePrototypeVariantA({
  state,
  dispatch,
}: {
  state: InviteProtoState;
  dispatch: InviteProtoDispatch;
}) {
  return (
    <div className="login-panel proto-inv-panel proto-inv-card" data-testid="proto-invite-a">
      <h1>CipherBox</h1>
      <p className="tagline">invite link</p>
      <InviteProtoHeader permission={state.permission} />
      <InviteProtoSignedInAs identifier={state.identifier} />
      <div className="proto-inv-section">
        <InviteProtoPlainList />
        <InviteProtoCounts />
      </div>
      <div className="proto-inv-section proto-inv-join">
        <InviteProtoNameField state={state} dispatch={dispatch} />
        <InviteProtoJoinButton dispatch={dispatch} />
      </div>
    </div>
  );
}
