/**
 * The tab's session, read from the engine rather than from a store of its own
 * (blueprint/web-client.md "UI state law": rendered state is the engine's word,
 * with no independent writers). The client publishes the account the origin's
 * engine holds; this is the `useSyncExternalStore` adapter over it.
 */

import { useSyncExternalStore } from 'react';
import { useEngine } from '../providers/EngineProvider';

const noSubscription = (): (() => void) => () => undefined;
const noAccount = (): string | null => null;

/**
 * The account the origin's engine holds for this tab, or `null` when it holds
 * none. A tab whose provider has not built a client yet reads the same as one
 * with no session: neither has an engine backing a vault.
 */
export function useEngineAccount(): string | null {
  const client = useEngine();
  return useSyncExternalStore(
    client?.subscribeSession ?? noSubscription,
    client?.signedInAccount ?? noAccount
  );
}
