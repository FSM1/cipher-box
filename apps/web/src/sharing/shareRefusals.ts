/** How a `share_scope` check name reads to the member; an unlisted one reaches them verbatim. */
export function refusalLabel(check: string): string {
  return SHARE_REFUSALS[check] ?? check;
}

const SHARE_REFUSALS: Record<string, string> = {
  'grant-target-is-the-vault-root': 'your whole vault cannot be shared — share a folder inside it',
  'invite-target-is-the-vault-root': 'your whole vault cannot be linked — link a folder inside it',
  'grant-target-already-names-a-scope':
    'this folder is already shared, so it takes no second grant of its own',
  'invite-target-already-names-a-scope':
    'this folder is already shared, so no further link can be minted here',
  'grant-parent-envelope-version-unsupported':
    'this vault was published by a newer build — update to grant here',
  'invite-parent-envelope-version-unsupported':
    'this vault was published by a newer build — update to mint a link here',
};
