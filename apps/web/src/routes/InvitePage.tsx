import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { LoginError } from '@cipherbox/auth-ui';
import { useAuth } from '../auth/useAuth';
import { SignInPanel } from '../components/auth/SignInPanel';
import { useEngineAccount } from '../engine/useEngineSession';
import { useCommandRunner } from '../hooks/useCommandRunner';

/** How far a claim got. The link itself is never one of these. */
type Progress = 'noLink' | 'claiming' | 'claimed' | 'refused';

/** What the page is showing, once the session it needs is folded in. */
type ClaimState = Progress | 'checking' | 'waiting' | 'ready';

/**
 * The invite claim route (blueprint/web-client.md "Composition"). The fragment
 * is the whole bearer capability, so it goes from `location.hash` to the facade
 * and nowhere else — unparsed, unrendered, and never in state.
 *
 * The claim needs a gesture. A mount-time claim would let any page that can
 * navigate a signed-in tab here — an `iframe`, a `window.open`, a mailed link —
 * spend an attacker's link under the member's identity, which posts their
 * contact code to a mailbox the link names and writes its minter into their
 * contact book (`crates/engine/src/facade.rs`, `claim_invite_link`).
 */
export function InvitePage() {
  const account = useEngineAccount();
  // A route outside `RequireAuth` still owes the engine the secret a restored
  // Core Kit session holds: without this hand-off the tab renders signed out
  // over a live login (`auth/useAuth.ts`).
  const { isSignedOut } = useAuth();
  const navigate = useNavigate();
  const { error, run } = useCommandRunner<'claimInviteLink'>();
  const [progress, setProgress] = useState<Progress | null>(null);
  // Read once, before the claim clears it: afterwards an empty hash means spent,
  // not absent.
  const [carriesLink] = useState(() => window.location.hash.length > 1);

  // Latched, so a sign-in in flight keeps the panel, and the progress it holds.
  const [decided, setDecided] = useState(false);
  if (isSignedOut && !decided) setDecided(true);

  const state: ClaimState =
    progress ??
    (account !== null ? (carriesLink ? 'ready' : 'noLink') : decided ? 'waiting' : 'checking');

  const claim = () => {
    if (progress !== null) return;
    const fragment = window.location.hash.slice(1);
    if (fragment === '') {
      setProgress('noLink');
      return;
    }
    // Through the router, so the capability leaves its in-memory location as
    // well as the address bar — and before the await, per
    // `EngineFacade.claimInviteLink`.
    navigate(`${window.location.pathname}${window.location.search}`, { replace: true });
    setProgress('claiming');
    void run('claimInviteLink', (facade) => facade.claimInviteLink(fragment)).then((accepted) =>
      setProgress(accepted ? 'claimed' : 'refused')
    );
  };

  return (
    <div className="login-container">
      <div className="login-panel" data-testid="invite-claim" data-state={state}>
        <h1>CipherBox</h1>
        <p className="tagline">invite link</p>
        <p className="login-description" data-testid="invite-status">
          {MESSAGES[state]}
        </p>
        {state === 'refused' && <LoginError message={error} />}
        {/* In place: a navigation away would drop the link with the address. */}
        {state === 'waiting' && <SignInPanel />}
        {state === 'ready' && (
          <>
            <p className="login-description" data-testid="invite-account">
              claiming as {account}
            </p>
            <button
              type="button"
              className="terminal-btn terminal-btn--filled"
              onClick={claim}
              data-testid="invite-claim-confirm"
            >
              claim this invite
            </button>
          </>
        )}
        {state === 'claimed' && (
          <Link className="terminal-btn" to="/files">
            go to your files
          </Link>
        )}
      </div>
    </div>
  );
}

/**
 * A claim reaches the owner's inbox; the grant it asks for is theirs to
 * complete, so this promises delivery and never access. A spent link leaves the
 * address bar, so a retry starts from wherever the member got it.
 */
const MESSAGES: Record<ClaimState, string> = {
  checking: 'checking whether this browser is signed in...',
  waiting: 'sign in here to claim this invite.',
  ready: 'this link shares a folder with you.',
  noLink: 'this address carries no invite link.',
  claiming: 'claiming...',
  claimed: 'claim sent. the folder shows up once the person who shared it accepts.',
  refused: 'this invite could not be claimed — open the link again to retry.',
};
