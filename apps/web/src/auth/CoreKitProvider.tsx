import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import type { CoreKitSession } from './coreKit';

export interface CoreKitContextValue {
  /** `null` until the session is built and its restore attempt has settled. */
  session: CoreKitSession | null;
  /** True while the mount-time session restore is still in flight. */
  isRestoring: boolean;
  /** Why Core Kit is unusable — a missing build config, or a failed restore. */
  error: string | null;
}

const CoreKitContext = createContext<CoreKitContextValue | undefined>(undefined);

export interface CoreKitProviderProps {
  /** Builds this tab's Core Kit session. Read once, on mount. */
  createSession: () => CoreKitSession;
  children: ReactNode;
}

/**
 * Owns the tab's one Core Kit session and its mount-time restore. Construction
 * runs in an effect so a StrictMode double-mount cannot leave two SDK instances
 * racing for the same storage.
 */
export function CoreKitProvider({ createSession, children }: CoreKitProviderProps) {
  const [value, setValue] = useState<CoreKitContextValue>({
    session: null,
    isRestoring: true,
    error: null,
  });
  const factory = useRef(createSession);

  useEffect(() => {
    let live = true;
    let session: CoreKitSession;
    try {
      session = factory.current();
    } catch (error) {
      setValue({ session: null, isRestoring: false, error: message(error) });
      return;
    }

    session
      .restore()
      .then(() => live && setValue({ session, isRestoring: false, error: null }))
      // A failed restore still yields a usable session to log in with.
      .catch(
        (error: unknown) => live && setValue({ session, isRestoring: false, error: message(error) })
      );

    return () => {
      live = false;
    };
  }, []);

  return <CoreKitContext.Provider value={value}>{children}</CoreKitContext.Provider>;
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** This tab's Core Kit session and its restore state. */
export function useCoreKit(): CoreKitContextValue {
  const value = useContext(CoreKitContext);
  if (!value) throw new Error('auth hooks must be used within <CoreKitProvider>');
  return value;
}
