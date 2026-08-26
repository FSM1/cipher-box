/**
 * This tab's half of the origin-wide session end another tab announced.
 *
 * `EngineClient` has already dropped its claim on the engine and torn itself out
 * by the time this runs (`subscribeSessionEnd`). What is left is the host's own
 * half — the Core Kit session and the auth chrome over it — which would
 * otherwise hand its secret straight back to the engine the rebuild spawns.
 *
 * Mounted once, at the app root: every `useAuth` consumer would otherwise drive
 * the teardown again.
 */

import { useEffect } from 'react';
import { useEngine } from '../providers/EngineProvider';
import { useAuth } from './useAuth';

export function useSessionEndAcrossTabs(): void {
  const client = useEngine();
  const { logout } = useAuth();

  useEffect(() => {
    if (!client) return;
    return client.subscribeSessionEnd(() => {
      // The session is already over; a refused teardown is not a failure the
      // front door can offer anything to do about.
      void logout().catch(() => undefined);
    });
  }, [client, logout]);
}
