// Share module barrel — export-only, no logic (coverage exclusion intentional: src/**/index.ts)

export { navigateReadChain, type NavigateResult } from './navigate';

export { issueReadGrant, claimInviteReadKey, type ReadGrantPayload } from './grant';
