/**
 * PROTOTYPE — throwaway. Variant B: two panes. The listing as a read-only file
 * browser on the left, a narrow "join" panel on the right.
 */
import {
  InviteProtoBrowserList,
  InviteProtoCounts,
  InviteProtoHeader,
  InviteProtoJoinButton,
  InviteProtoNameField,
  InviteProtoSignedInAs,
} from './InvitePrototypeParts';
import {
  INVITE_PROTO_FOLDER,
  type InviteProtoDispatch,
  type InviteProtoState,
} from './InvitePrototypeStore';

export function InvitePrototypeVariantB({
  state,
  dispatch,
}: {
  state: InviteProtoState;
  dispatch: InviteProtoDispatch;
}) {
  return (
    <div className="login-panel proto-inv-panel proto-inv-wide" data-testid="proto-invite-b">
      <h1>CipherBox</h1>
      <p className="tagline">invite link</p>
      <div className="proto-inv-panes">
        <section className="proto-inv-pane-left" aria-label="preview">
          <div className="proto-inv-pane-bar">
            <nav className="breadcrumb-nav" aria-label="Preview location">
              <span className="breadcrumb-prefix">~</span>
              <span className="breadcrumb-separator">/</span>
              <span className="breadcrumb-item breadcrumb-item--current">
                {INVITE_PROTO_FOLDER.name}
              </span>
            </nav>
            <span className="proto-inv-tag">read-only preview</span>
          </div>
          <InviteProtoBrowserList locked />
          <InviteProtoCounts />
        </section>
        <aside className="proto-inv-pane-right" aria-label="join">
          <InviteProtoHeader permission={state.permission} size="sm" />
          <InviteProtoSignedInAs identifier={state.identifier} />
          <InviteProtoNameField state={state} dispatch={dispatch} />
          <InviteProtoJoinButton dispatch={dispatch} />
          <p className="proto-inv-dim proto-inv-xsmall">
            nothing is saved until you join. leave this page and the preview is gone.
          </p>
        </aside>
      </div>
    </div>
  );
}
