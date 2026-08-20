import { Navigate } from 'react-router-dom';
import type { ReactNode } from 'react';
import { useAuth } from './useAuth';

/**
 * Sends a tab with no session back to the front door. `isSignedOut` settles
 * only once this tab knows it has no vault, so a Core Kit restore or a secret
 * handoff still in flight renders on rather than throwing the member out of
 * their own files.
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { isSignedOut } = useAuth();
  if (isSignedOut) return <Navigate to="/" replace />;
  return <>{children}</>;
}
