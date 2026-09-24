/**
 * PROTOTYPE — throwaway. The invite route under `?variant=A|B|C`: the flow from
 * arrival to the shared folder on stub data. No engine, facade, or auth call.
 */
import type { ReactNode } from 'react';
import {
  InviteProtoFolderView,
  InviteProtoJoined,
  InviteProtoSignedOut,
  inviteProtoStatusScreen,
} from './InvitePrototypeParts';
import { InvitePrototypeStatePanel } from './InvitePrototypeStatePanel';
import { useInvitePrototypeStore } from './InvitePrototypeStore';
import { InvitePrototypeSwitcher } from './InvitePrototypeSwitcher';
import { useInvitePrototypeVariant, type InviteProtoVariant } from './InvitePrototypeVariant';
import { InvitePrototypeVariantA } from './InvitePrototypeVariantA';
import { InvitePrototypeVariantB } from './InvitePrototypeVariantB';
import { InvitePrototypeVariantC } from './InvitePrototypeVariantC';
import './InvitePrototype.css';

const VARIANTS = {
  A: InvitePrototypeVariantA,
  B: InvitePrototypeVariantB,
  C: InvitePrototypeVariantC,
} as const;

/** Renders the prototype when `?variant=` names one, else the real page. */
export function InvitePrototypeGate({ children }: { children: ReactNode }) {
  const variant = useInvitePrototypeVariant();
  return variant === null ? children : <InvitePrototypePage variant={variant} />;
}

function InvitePrototypePage({ variant }: { variant: InviteProtoVariant }) {
  const [state, dispatch] = useInvitePrototypeStore();
  const Variant = VARIANTS[variant];

  let body: ReactNode;
  if (state.phase === 'signed-out') body = <InviteProtoSignedOut dispatch={dispatch} />;
  else if (state.phase === 'in-folder') body = <InviteProtoFolderView state={state} />;
  else if (state.phase === 'joined') body = <InviteProtoJoined state={state} dispatch={dispatch} />;
  else
    body = inviteProtoStatusScreen(state, dispatch) ?? (
      <Variant state={state} dispatch={dispatch} />
    );

  return (
    <div className="login-container proto-inv-page" data-state={state.phase}>
      {body}
      <InvitePrototypeStatePanel state={state} dispatch={dispatch} />
      <InvitePrototypeSwitcher current={variant} />
    </div>
  );
}
