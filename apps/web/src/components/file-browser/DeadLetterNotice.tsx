import type { DeadLetterDescriptor, DeadLetterReason } from '@cipherbox/client';

/** Why the op is terminal, in the words the reader needs, not the engine's. */
const REASONS: Record<DeadLetterReason, string> = {
  targetGone: 'its target no longer exists',
  destinationGone: 'its destination no longer exists',
  destinationInsideTarget: 'the destination is inside the folder being moved',
  suffixExhausted: 'no free name was left in the destination',
  undecodable: 'the queued change could not be read back',
  payloadRefused: 'the network refused the payload',
  attemptsExhausted: 'it failed too many times',
  contentUnrecoverable: 'its content could not be recovered',
  baseSuperseded: 'someone else saved a newer version first, so this edit was not published',
  headTooLarge:
    "this item's record grew too large to save; it has to hold less — a folder by splitting it into subfolders, a file by keeping fewer old versions",
  preservationRefused:
    'this device holds parked changes another version of CipherBox wrote, so this one could not be parked beside them',
  alreadyPublished:
    'this device already created this item once; the queued copy is older than what is online, so it was not created again',
  targetStillLinked:
    'this item is still in one of your folders, so it was not permanently deleted from the bin',
  scopeRootNotResealable:
    "this shared folder's own record leaves no room for the re-key a revoke needs; the folder has to carry fewer direct subfolders or fewer people before it can be saved",
  binIndexFull:
    'your bin is full, so this item could not be moved to it; empty the bin, or delete this item permanently',
  crossingUnauthorable:
    'this item would end up in a different shared folder than the one it came from, which CipherBox cannot do in one step; move it to a folder you do not share first, then into the one you want',
  binIndexStrandedMint:
    'this device cannot read your bin, and its own first attempt to set one up did not finish, so it cannot move this item there; sign in on another device to repair the bin, or delete this item permanently',
};

/**
 * Dead letters are terminal: nothing retries them and nothing clears them on a
 * later pull, so the notice stays up for as long as the engine reports them.
 */
export function DeadLetterNotice({ deadLetters }: { deadLetters: DeadLetterDescriptor[] }) {
  if (deadLetters.length === 0) return null;

  return (
    <div className="dead-letter-notice" role="alert" data-testid="dead-letter-notice">
      <p className="dead-letter-notice-title">
        {`[!] ${deadLetters.length} change${deadLetters.length === 1 ? '' : 's'} will never publish`}
      </p>
      <ul className="dead-letter-notice-list">
        {deadLetters.map((letter) => (
          <li key={String(letter.opId)}>{REASONS[letter.reason]}</li>
        ))}
      </ul>
    </div>
  );
}
