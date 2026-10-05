import type { CoreKitSession } from './session';

const RETRY_WINDOW_MS = 120_000;

function retryableExportFailure(failure: unknown): boolean {
  if (failure instanceof Error) {
    return (
      failure.message === 'master poly commits inconsistent with tssPubKey' ||
      /^all auth network nodes are currently busy\b/i.test(failure.message)
    );
  }
  // Web3Auth's HTTP helper throws a Response; its body and query may contain credentials.
  if (typeof failure !== 'object' || failure === null) return false;
  const { status, url } = failure as { status?: unknown; url?: unknown };
  if (typeof status !== 'number' || status < 500 || status >= 600 || typeof url !== 'string') {
    return false;
  }
  try {
    const target = new URL(url);
    return target.protocol === 'https:' && target.hostname.endsWith('.web3auth.io');
  } catch {
    return false;
  }
}

function pause(ms: number, signal: AbortSignal): Promise<void> {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const aborted = () => {
      clearTimeout(timer);
      reject(signal.reason);
    };
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', aborted);
      resolve();
    }, ms);
    signal.addEventListener('abort', aborted, { once: true });
  });
}

/** Retries only the SDK export: decoding and engine trust checks run once, outside this loop. */
export async function exportRestoredSecret(
  session: CoreKitSession,
  signal: AbortSignal,
  now: () => Date
): Promise<string> {
  const deadline = now().getTime() + RETRY_WINDOW_MS;
  let lastFailure: unknown;
  for (let attempt = 0; ; attempt += 1) {
    signal.throwIfAborted();
    if (!session.isLoggedIn()) throw new Error('the saved login session has expired');
    if (attempt > 0 && now().getTime() >= deadline) throw lastFailure;
    try {
      // The SDK cannot cancel an export; settle it before another attempt or handoff.
      const secret = await session._UNSAFE_exportTssKey();
      signal.throwIfAborted();
      if (!session.isLoggedIn()) throw new Error('the saved login session has expired');
      return secret;
    } catch (failure) {
      signal.throwIfAborted();
      if (!retryableExportFailure(failure)) throw failure;
      lastFailure = failure;
      const delay = (attempt === 0 ? 15_000 : 25_000) + Math.floor(Math.random() * 5_000);
      if (now().getTime() + delay >= deadline) throw failure;
      await pause(delay, signal);
    }
  }
}
