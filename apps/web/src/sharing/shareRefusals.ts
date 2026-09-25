/** How a sharing check name reads to the member; an unlisted one reaches them verbatim. */
export function refusalLabel(check: string): string {
  // `hasOwn`, so a name that collides with a prototype key reads as itself
  // rather than as whatever `Object.prototype` carries under it.
  return Object.hasOwn(SHARE_REFUSALS, check) ? SHARE_REFUSALS[check] : check;
}

/**
 * How a refused sharing command reads to the member. The engine renders a
 * check-bearing refusal as `<class>: <check>` (`EngineError`'s `Display`), so
 * a listed check reads in words and anything else reaches them verbatim.
 */
export function refusalText(message: string): string {
  const check = message.slice(message.lastIndexOf(': ') + 2);
  return Object.hasOwn(SHARE_REFUSALS, check) ? SHARE_REFUSALS[check] : message;
}

const SHARE_REFUSALS: Record<string, string> = {
  'grant-target-is-the-vault-root': 'your whole vault cannot be shared — share a folder inside it',
  'invite-target-is-the-vault-root': 'your whole vault cannot be linked — link a folder inside it',
  'grant-target-index-lost-a-root':
    'an earlier share of this folder did not finish and cannot be resumed, so it takes no grant',
  'invite-target-index-lost-a-root':
    'an earlier share of this folder did not finish and cannot be resumed, so no link can be minted here',
  'grant-recipient-already-has-access': 'this person already has that access',
  'grant-recipient-not-granted': 'this person holds no grant on this folder',
  'grant-recipient-key-changed':
    "this person's key changed since the grant — revoke it and share again",
  'link-ambiguous': 'this folder carries more than one link — pick the one to revoke',
  'link-not-committed': 'this link is no longer on the folder',
  'grant-row-is-a-link':
    "a link's access is fixed when it is minted — revoke it and mint a new one",
  'resume-not-this-grant':
    'this folder already carries a share of its own, so it takes no second one',
  'grant-parent-envelope-version-unsupported':
    'this vault was published by a newer build — update to grant here',
  'invite-parent-envelope-version-unsupported':
    'this vault was published by a newer build — update to mint a link here',
  'grant-set-full': 'this folder is shared with as many people and links as it can hold',
  'recipient-is-the-owner': 'you already own this folder',
  'recipient-not-imported': 'import this contact before you share with them',
  'invalid-grantee-name': 'a name needs at least one character and no control characters',
  'invite-name-too-long': 'your name on the link is too long',
  'grant-display-name-too-long': 'the folder name is too long to share — rename it first',
  'invite-link-contact-budget-full':
    'the links on this vault hold all the people they can — revoke a link to free room',
  'rename-target-is-not-a-scope-root': 'this folder is not shared, so it has no one to rename',
  'revoke-target-is-not-a-scope-root': 'this folder is not shared, so it has no one to revoke',
  'revoke-link-target-is-not-a-scope-root': 'this folder carries no link to revoke',
  'convert-target-is-not-a-scope-root': 'this folder carries no link, so no one can join it',
};
