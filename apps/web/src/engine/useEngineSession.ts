import { useSyncExternalStore } from 'react';
import { useEngine } from '../providers/EngineProvider';

/** Stands in before the provider has built a client: no engine, so no session. */
const noEngine = {
  subscribeSession: () => () => undefined,
  signedInAccount: (): string | null => null,
};

/**
 * The account the origin's engine holds for this tab (`EngineClient`), as the
 * one subscription store the UI reads sign-in from.
 */
export function useEngineAccount(): string | null {
  const { subscribeSession, signedInAccount } = useEngine() ?? noEngine;
  return useSyncExternalStore(subscribeSession, signedInAccount);
}
