import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useEngineAccount } from '../engine/useEngineSession';
import { useCommandRunner } from '../hooks/useCommandRunner';

/** How far the claim got. The link itself is never one of these. */
type ClaimState = 'waiting' | 'noLink' | 'claiming' | 'claimed' | 'refused';

/**
 * The invite claim route (blueprint/web-client.md "Composition"). The fragment
 * is the whole bearer capability, so it goes from `location.hash` to the facade
 * and nowhere else — unparsed, unrendered, and never in state.
 */
export function InvitePage() {
  const account = useEngineAccount();
  const { error, run } = useCommandRunner<'claimInviteLink'>();
  const [state, setState] = useState<ClaimState>('waiting');
  const spent = useRef(false);

  useEffect(() => {
    if (account === null || spent.current) return;
    spent.current = true;
    const fragment = window.location.hash.slice(1);
    if (fragment === '') {
      setState('noLink');
      return;
    }
    // Cleared before the await, per `EngineFacade.claimInviteLink`, and through
    // `history` so the restorable entry loses it too.
    window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
    setState('claiming');
    void run('claimInviteLink', (facade) => facade.claimInviteLink(fragment)).then((accepted) =>
      setState(accepted ? 'claimed' : 'refused')
    );
  }, [account, run]);

  return (
    <div className="login-container">
      <div className="login-panel" data-testid="invite-claim" data-state={state}>
        <h1>CipherBox</h1>
        <p className="tagline">invite link</p>
        <p className="login-description" data-testid="invite-status">
          {MESSAGES[state]}
        </p>
        {state === 'refused' && error !== null && (
          <p className="dialog-error" role="alert" data-testid="invite-error">
            {error}
          </p>
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
 * complete, so this promises delivery and never access.
 */
const MESSAGES: Record<ClaimState, string> = {
  waiting: 'sign in to claim this invite — reopen the link once you have.',
  noLink: 'this address carries no invite link.',
  claiming: 'claiming...',
  claimed: 'claim sent. the folder shows up once the person who shared it accepts.',
  refused: 'this invite could not be claimed.',
};
