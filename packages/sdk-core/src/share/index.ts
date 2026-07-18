// Share module barrel — export-only, no logic (coverage exclusion intentional: src/**/index.ts)

export { navigateReadChain, type NavigateResult } from './navigate';

export { issueReadGrant, claimInviteReadKey, claimInvite, type ReadGrantPayload } from './grant';

export {
  assertRecipientPinned,
  appendRecipientPin,
  extractRecipientPins,
  type RecipientPubkey,
} from './recipient-pins';
