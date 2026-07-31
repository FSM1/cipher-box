import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { errorMessage } from '../lib/errorMessage';
import type { CoreKitSession } from './coreKit';

export interface CoreKitContextValue {
  /** `null` until the session is built and its restore attempt has settled. */
  session: CoreKitSession | null;
  /** True while the mount-time session restore is still in flight. */
  isRestoring: boolean;
  /** Why Core Kit is unusable at all — a missing or rejected build config. */
  error: string | null;
}

const CoreKitContext = createContext<CoreKitContextValue | undefined>(undefined);

export interface CoreKitProviderProps {
  /** Builds this tab's Core Kit session. Called once per tab. */
  createSession: () => CoreKitSession;
  children: ReactNode;
}

/**
 * Owns the tab's one Core Kit session and its mount-time restore. The session
 * and the restore promise are both latched in refs: the SDK holds a device
 * factor in origin storage, so a StrictMode remount must reuse the instance
 * rather than race a second one against the same store.
 */
export function CoreKitProvider({ createSession, children }: CoreKitProviderProps) {
  const [value, setValue] = useState<CoreKitContextValue>({
    session: null,
    isRestoring: true,
    error: null,
  });
  const factory = useRef(createSession);
  const session = useRef<CoreKitSession | null>(null);
  const restore = useRef<Promise<void> | null>(null);

  useEffect(() => {
    let live = true;
    try {
      session.current ??= factory.current();
      restore.current ??= session.current.restore();
    } catch (error) {
      setValue({ session: null, isRestoring: false, error: errorMessage(error) });
      return;
    }

    const settled = { session: session.current, isRestoring: false, error: null };
    // A failed restore just means there is no session to resume; the methods
    // below still work, and a real breakage surfaces when one is used.
    restore.current.then(
      () => live && setValue(settled),
      () => live && setValue(settled)
    );

    return () => {
      live = false;
    };
  }, []);

  return <CoreKitContext.Provider value={value}>{children}</CoreKitContext.Provider>;
}

/** This tab's Core Kit session and its restore state. */
export function useCoreKit(): CoreKitContextValue {
  const value = useContext(CoreKitContext);
  if (!value) throw new Error('auth hooks must be used within <CoreKitProvider>');
  return value;
}
