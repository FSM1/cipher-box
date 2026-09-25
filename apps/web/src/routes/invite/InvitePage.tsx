import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import type { InvitePreviewDescriptor } from '@cipherbox/client';
import { LoginError } from '@cipherbox/auth-ui';
import { useAuth } from '../../auth/useAuth';
import { SignInPanel } from '../../components/auth/SignInPanel';
import { useEngineAccount } from '../../engine/useEngineSession';
import { errorMessage } from '../../lib/errorMessage';
import { folderPath } from '../../lib/nodeId';
import { useEngine } from '../../providers/EngineProvider';
import { InviteCard } from './InviteCard';
import {
  failedPreviewOutcome,
  previewOutcome,
  type PreviewFailure,
  type PreviewOutcome,
} from './invitePreview';

/** What the page is showing, once the session it needs is folded in. */
type InviteState =
  | 'checking'
  | 'waiting'
  | 'noLink'
  | 'previewing'
  | PreviewOutcome
  | 'joining'
  | 'refused';

/** A read, keyed by the account and the link it was read for. */
type Preview = { account: string; fragment: string } & (
  | { outcome: 'read'; preview: InvitePreviewDescriptor }
  | { outcome: PreviewFailure }
);

/** One press of "join": the link and account it claims for, and its own result. */
type Joining = { read: InvitePreviewDescriptor; claimed: string; account: string } & (
  | { step: 'joining' }
  | { step: 'refused'; refusal: string }
);

/** The address names a link other than the one claimed: the member moved on. */
const movedOn = (claimed: string, fragment: string) => fragment !== '' && fragment !== claimed;

/**
 * The invite route (blueprint/web-client.md "Composition"): sign-in, then the
 * preview, then "join" (ADR 0028 D1). The fragment is the whole bearer
 * capability, so it goes from the router's `hash` to the facade, unparsed and
 * unrendered. The preview keeps it only to bind "join" to the link on screen.
 *
 * The preview spends and stores nothing, so it runs with no press. The join
 * needs a gesture: a mount-time join would let any page that can navigate a
 * signed-in tab here spend an attacker's link under the member's identity
 * (`crates/engine/src/facade.rs`, `claim_invite_link`).
 */
export function InvitePage() {
  const account = useEngineAccount();
  // A route outside `RequireAuth` still owes the engine the secret a restored
  // Core Kit session holds: without this hand-off the tab renders signed out
  // over a live login (`auth/useAuth.ts`).
  const { isSignedOut } = useAuth();
  const client = useEngine();
  const navigate = useNavigate();
  const fragment = useLocation().hash.slice(1);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [joining, setJoining] = useState<Joining | null>(null);
  // Mirrors `joining`, so a claim that settles late sees whether it is still on screen.
  const onScreen = useRef<Joining | null>(null);
  useLayoutEffect(() => {
    onScreen.current = joining;
  }, [joining]);

  // Latched, so a sign-in in flight keeps the panel, and the progress it holds.
  const [decided, setDecided] = useState(false);
  if (isSignedOut && !decided) setDecided(true);
  if (account === null && preview !== null) setPreview(null);
  if (joining !== null && (movedOn(joining.claimed, fragment) || joining.account !== account)) {
    setJoining(null);
  }

  useEffect(() => {
    if (account === null || client === null || fragment === '') return;
    let current = true;
    client.facade.previewInviteLink(fragment).then(
      (read) => current && setPreview({ account, fragment, outcome: 'read', preview: read }),
      (failure: unknown) =>
        current && setPreview({ account, fragment, outcome: failedPreviewOutcome(failure) })
    );
    return () => {
      current = false;
    };
  }, [account, client, fragment]);

  // A read for another account or another link shows nothing, so no action
  // offered can act on what the page no longer names.
  const shown = preview?.account === account && preview.fragment === fragment ? preview : null;
  const signedIn = account !== null && client !== null;
  const state: InviteState =
    joining?.step ?? (signedIn ? linkState(fragment, shown) : decided ? 'waiting' : 'checking');

  /**
   * Through the router, so the capability leaves its in-memory location as
   * well as the address bar, and the back entry that held it.
   */
  const openFolder = (scope: Uint8Array) => navigate(folderPath(scope), { replace: true });

  /** Claims exactly the link the shown preview was read for. */
  const join = (
    { fragment: claimed, account: claimant }: Preview,
    read: InvitePreviewDescriptor,
    name: string
  ) => {
    if (joining?.step === 'joining' || client === null) return;
    // Before the await, per `EngineFacade.claimInviteLink`.
    navigate(`${window.location.pathname}${window.location.search}`, { replace: true });
    setPreview(null);
    const attempt: Joining = { step: 'joining', read, claimed, account: claimant };
    setJoining(attempt);
    // The router applies a new address in a transition, so the address bar can
    // lead `onScreen` by a render.
    const stillOnScreen = () =>
      onScreen.current === attempt && !movedOn(claimed, window.location.hash.slice(1));
    void client.facade.claimInviteLink(claimed, name).then(
      () => stillOnScreen() && openFolder(read.scope),
      (refusal: unknown) =>
        stillOnScreen() &&
        setJoining({ ...attempt, step: 'refused', refusal: errorMessage(refusal) })
    );
  };

  const read = joining?.read ?? (shown?.outcome === 'read' ? shown.preview : null);

  return (
    <div className="login-container">
      <div className="login-panel invite-panel" data-testid="invite-claim" data-state={state}>
        <h1>CipherBox</h1>
        <p className="tagline">invite link</p>
        {MESSAGES[state] !== null && (
          <p className="login-description" data-testid="invite-status" role="status">
            {MESSAGES[state]}
          </p>
        )}
        {joining?.step === 'refused' && <LoginError message={joining.refusal} />}
        {/* In place: a navigation away would drop the link with the address. */}
        {state === 'waiting' && <SignInPanel />}
        {read !== null && (state === 'joinable' || state === 'joining') && (
          <>
            <p className="invite-dim" data-testid="invite-account">
              signed in as {account}
            </p>
            <InviteCard
              preview={read}
              joining={state === 'joining'}
              focusJoin={decided}
              onJoin={(name) => shown !== null && join(shown, read, name)}
            />
          </>
        )}
        {read !== null && state === 'joined' && (
          <button
            autoFocus={decided}
            type="button"
            className="terminal-btn terminal-btn--filled"
            onClick={() => openFolder(read.scope)}
            data-testid="invite-open-folder"
          >
            open folder
          </button>
        )}
      </div>
    </div>
  );
}

function linkState(fragment: string, preview: Preview | null): InviteState {
  if (fragment === '') return 'noLink';
  if (preview === null) return 'previewing';
  return preview.outcome === 'read' ? previewOutcome(preview.preview) : preview.outcome;
}

/**
 * `null` where the card itself carries the page. A dead link leaves the
 * address bar as it is, so a retry starts from wherever the member got it.
 */
const MESSAGES: Record<InviteState, string | null> = {
  checking: 'checking whether this browser is signed in...',
  waiting: 'this link shares a folder with you. sign in to see what is inside.',
  noLink: 'this address carries no invite link.',
  previewing: 'reading the shared folder...',
  joinable: null,
  joining: null,
  joined: 'you already joined this folder.',
  expired: 'this link has expired. ask the owner for a new link.',
  revoked: 'the owner turned this link off. ask the owner for a new link.',
  unresolvable: 'the shared folder could not be reached. open the link again later.',
  untrusted:
    'this link failed a trust check. the folder it names does not verify, so nothing was read.',
  unreadable: 'this link could not be read. open the link again to retry.',
  refused: 'the join did not complete. open the link again to retry.',
};
