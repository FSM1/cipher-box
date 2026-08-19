import { shortAccountId } from '../../lib/accountId';

/**
 * The origin hosts one engine, so it hosts one account: a sign-in this browser
 * already has another tab's session for is refused rather than served that
 * tab's vault (blueprint/web-client.md "Engine hosting and tab leadership").
 * Only the tab holding the engine can give it up, so the way out is stated
 * there rather than offered as a button here.
 */
export function SignedInElsewhere({ heldBy }: { heldBy: string | null }) {
  return (
    <div className="login-error" role="alert" aria-live="polite">
      <p>
        {heldBy === null
          ? 'another tab in this browser is running CipherBox and is not signed in.'
          : `another account is already signed in to CipherBox in this browser: ${shortAccountId(heldBy)}.`}
      </p>
      <p>sign out in that tab, or close it, then sign in again here.</p>
    </div>
  );
}
