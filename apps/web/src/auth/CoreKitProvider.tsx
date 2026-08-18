import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { errorMessage } from '../lib/errorMessage';
import type { WebCoreKitSession } from './coreKit';

/** Whether this tab knows if it has a session. */
export type CoreKitStatus = 'checking' | 'ready' | 'unavailable';

/** Generous, so a slow-but-working restore still lands `ready`. */
const RESTORE_DEADLINE_MS = 10_000;

const UNREACHABLE = 'the login provider is not responding — check your connection and reload';

/**
 * Deliberately says nothing about the cause: the throw that gets here is
 * usually the SDK parsing its own store, and that message quotes the bytes it
 * choked on, which are bearer key material.
 */
const RESTORE_FAILED = 'the saved sign-in could not be restored — please sign in again';

export interface CoreKitContextValue {
  /** `null` until the session is built and its restore attempt has settled. */
  session: WebCoreKitSession | null;
  status: CoreKitStatus;
  /** Why this tab has no session — a bad build config, silence, or a failed restore. */
  error: string | null;
}

const CoreKitContext = createContext<CoreKitContextValue | undefined>(undefined);

export interface CoreKitProviderProps {
  /** Builds this tab's Core Kit session. Called once per tab. */
  createSession: () => WebCoreKitSession;
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
  const session = useRef<WebCoreKitSession | null>(null);
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
    // `checking` forever, so silence past the deadline is a verdict.
    const deadline = setTimeout(() => {
      if (live) setValue({ session: null, status: 'unavailable', error: UNREACHABLE });
    }, RESTORE_DEADLINE_MS);

    const restored = session.current;
    const settle = (error: string | null) => {
      clearTimeout(deadline);
      if (live) setValue({ session: restored, status: 'ready', error });
    };
    // A rejected restore resumes nothing, so the tab still lands at the front
    // door — but it lands there carrying the failure, not as a clean sign-out.
    // The session stays in hand because logging in again is the way out of it.
    restore.current.then(
      () => settle(null),
      () => settle(RESTORE_FAILED)
    );

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
