import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { InvitePreviewDescriptor } from '@cipherbox/client';
import { LoginError } from '@cipherbox/auth-ui';
import { useAuth } from '../../auth/useAuth';
import { SignInPanel } from '../../components/auth/SignInPanel';
import { useEngineAccount } from '../../engine/useEngineSession';
import { useCommandRunner } from '../../hooks/useCommandRunner';
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

type Preview = { outcome: 'read'; preview: InvitePreviewDescriptor } | { outcome: PreviewFailure };

/**
 * The invite route (blueprint/web-client.md "Composition"): sign-in, then the
 * preview, then "join" (ADR 0028 D1). The fragment is the whole bearer
 * capability, so it goes from `location.hash` to the facade and nowhere else —
 * unparsed, unrendered, and never in state.
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
  const { error, run } = useCommandRunner<'claimInviteLink'>();
  const [preview, setPreview] = useState<Preview | null>(null);
  const [joining, setJoining] = useState<'joining' | 'refused' | null>(null);
  // Read once, before the join clears it: afterwards an empty hash means spent,
  // not absent.
  const [carriesLink] = useState(() => window.location.hash.length > 1);

  // Latched, so a sign-in in flight keeps the panel, and the progress it holds.
  const [decided, setDecided] = useState(false);
  if (isSignedOut && !decided) setDecided(true);

  const signedIn = account !== null && client !== null;
  useEffect(() => {
    if (!signedIn || !carriesLink || client === null) return;
    let current = true;
    client.facade.previewInviteLink(window.location.hash.slice(1)).then(
      (read) => current && setPreview({ outcome: 'read', preview: read }),
      (failure: unknown) => current && setPreview({ outcome: failedPreviewOutcome(failure) })
    );
    return () => {
      current = false;
    };
  }, [signedIn, carriesLink, client]);

  const state: InviteState =
    joining ?? (signedIn ? linkState(carriesLink, preview) : decided ? 'waiting' : 'checking');

  /**
   * Through the router, so the capability leaves its in-memory location as
   * well as the address bar, and the back entry that held it.
   */
  const openFolder = (scope: Uint8Array) => navigate(folderPath(scope), { replace: true });

  const join = (scope: Uint8Array, name: string) => {
    if (joining === 'joining') return;
    const fragment = window.location.hash.slice(1);
    if (fragment === '') return;
    // Before the await, per `EngineFacade.claimInviteLink`.
    navigate(`${window.location.pathname}${window.location.search}`, { replace: true });
    setJoining('joining');
    void run('claimInviteLink', (facade) => facade.claimInviteLink(fragment, name)).then(
      (accepted) => {
        if (accepted) openFolder(scope);
        else setJoining('refused');
      }
    );
  };

  const read = preview?.outcome === 'read' ? preview.preview : null;

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
        {state === 'refused' && <LoginError message={error} />}
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
              onJoin={(name) => join(read.scope, name)}
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

function linkState(carriesLink: boolean, preview: Preview | null): InviteState {
  if (!carriesLink) return 'noLink';
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
