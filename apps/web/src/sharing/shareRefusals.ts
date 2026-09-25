/** How a sharing check name reads to the member; an unlisted one reaches them verbatim. */
export function refusalLabel(check: string): string {
  // `hasOwn`, so a name that collides with a prototype key reads as itself
  // rather than as whatever `Object.prototype` carries under it.
  return Object.hasOwn(SHARE_REFUSALS, check) ? SHARE_REFUSALS[check] : check;
}

const SHARE_REFUSALS: Record<string, string> = {
  'grant-target-is-the-vault-root': 'your whole vault cannot be shared — share a folder inside it',
  'invite-target-is-the-vault-root': 'your whole vault cannot be linked — link a folder inside it',
  'grant-target-index-lost-a-root':
    'an earlier share of this folder did not finish and cannot be resumed, so it takes no grant',
  'invite-target-index-lost-a-root':
    'an earlier share of this folder did not finish and cannot be resumed, so no link can be minted here',
  'grant-recipient-already-has-access': 'this contact already has that access',
  'grant-recipient-not-granted': 'this contact holds no grant on this folder',
  'grant-recipient-key-changed':
    "this contact's key changed since the grant — revoke it and share again",
  'link-ambiguous': 'this folder carries more than one link — pick the one to revoke',
  'grant-row-is-a-link':
    "a link's access is fixed when it is minted — revoke it and mint a new one",
  'resume-not-this-grant':
    'this folder already carries a share of its own, so it takes no second one',
  'grant-parent-envelope-version-unsupported':
    'this vault was published by a newer build — update to grant here',
  'invite-parent-envelope-version-unsupported':
    'this vault was published by a newer build — update to mint a link here',
};
