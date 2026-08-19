import { LoginError } from './LoginError';
import { shortAccountId } from '../../utils/format';

/**
 * The origin hosts one engine, so it hosts one account: a sign-in this browser
 * already has another tab's session for is refused rather than served that
 * tab's vault (blueprint/web-client.md "Engine hosting and tab leadership").
 * Only the tab holding the engine can give it up, so the way out is stated
 * here rather than offered as a button that cannot reach it.
 */
export function SignedInElsewhere({ heldBy }: { heldBy: string | null }) {
  return (
    <LoginError
      message={
        <>
          <p>
            {heldBy === null
              ? 'another tab in this browser is running CipherBox and is not signed in.'
              : `another account is already signed in to CipherBox in this browser: ${shortAccountId(heldBy)}.`}
          </p>
          <p>sign out in that tab, or close it, then sign in again here.</p>
        </>
      }
    />
  );
}
