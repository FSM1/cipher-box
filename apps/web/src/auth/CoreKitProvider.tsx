import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { errorMessage } from '../lib/errorMessage';
import type { CoreKitSession } from './coreKit';

/**
 * Whether this tab knows if it has a session. `unavailable` is a verdict, not a
 * stage on the way to `ready`: a route gating on it has its answer.
 */
export type CoreKitStatus = 'checking' | 'ready' | 'unavailable';

/**
 * How long the mount-time restore may run before the tab calls Core Kit
 * unreachable. Generous, so a slow-but-working restore still lands `ready`.
 */
const RESTORE_DEADLINE_MS = 10_000;

const UNREACHABLE = 'the login provider is not responding — check your connection and reload';

export interface CoreKitContextValue {
  /** `null` until the session is built and its restore attempt has settled. */
  session: CoreKitSession | null;
  status: CoreKitStatus;
  /** Why Core Kit is unusable at all — a bad build config, or silence. */
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
    status: 'checking',
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
      setValue({ session: null, status: 'unavailable', error: errorMessage(error) });
      return;
    }

    // A restore that never settles would hold every route gating on this at
    // `checking` forever; the deadline turns that silence into a verdict, and a
    // restore that lands late still promotes the tab back to `ready`.
    const deadline = setTimeout(() => {
      if (live) setValue({ session: null, status: 'unavailable', error: UNREACHABLE });
    }, RESTORE_DEADLINE_MS);

    const settled: CoreKitContextValue = {
      session: session.current,
      status: 'ready',
      error: null,
    };
    // A failed restore just means there is no session to resume; the methods
    // below still work, and a real breakage surfaces when one is used.
    const settle = () => {
      clearTimeout(deadline);
      if (live) setValue(settled);
    };
    restore.current.then(settle, settle);

    return () => {
      live = false;
      clearTimeout(deadline);
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
