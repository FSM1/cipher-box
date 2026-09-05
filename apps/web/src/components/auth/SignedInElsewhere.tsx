import { LoginError } from '@cipherbox/auth-ui';
import { shortAccountId } from '../../utils/format';

/**
 * What a sign-in refused by the origin's one engine shows (`PortRequest`). Only
 * the tab holding that engine can give it up, so the way out is stated here
 * rather than offered as a button that cannot reach it.
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
