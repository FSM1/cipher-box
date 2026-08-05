/**
 * Binds the engine's trust warnings to the warning-notice surface. A withheld
 * update and an attributable-abuse report are verdicts about what the network
 * served, so they render as their own class and never move the staleness ladder
 * (blueprint/web-client.md "Staleness ladder rendering", AGENTS.md rule 6).
 */

import { useEffect } from 'react';
import { toHex } from '@cipherbox/client';
import { useEngine } from '../providers/EngineProvider';
import { notificationStore } from '../stores/notification.store';

/**
 * The pinned name identifies the scope for de-duplication only. It is a routing
 * identifier the reader cannot act on, so the notice reads in vault terms.
 */
const WITHHELD =
  'a shared folder stopped serving updates you are entitled to see — what it shows may be behind';

export function useEngineNotices(): void {
  const client = useEngine();

  useEffect(() => {
    if (client === null) return;
    const unsubscribe = client.facade.subscribe((event) => {
      if (event.kind === 'withheldUpdateEscalation') {
        notificationStore.warn(`withheld:${toHex(event.ipnsName)}`, WITHHELD);
      } else if (event.kind === 'attributableAbuse') {
        notificationStore.warn(
          `abuse:${event.description}`,
          `verification refused an update: ${event.description}`
        );
      }
    });
    return () => {
      unsubscribe();
      notificationStore.clear();
    };
  }, [client]);
}
