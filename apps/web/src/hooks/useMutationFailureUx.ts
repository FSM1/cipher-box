/**
 * useMutationFailureUx -- Fail-closed error classification + failure UX (Phase 68).
 *
 * The SDK/resolve layer already enforces every rotation-safety decision
 * fail-closed (68-01 durable anti-rollback floors, 68-05 reconcile-before-
 * publish defer, 68-06 wiring of the regression gate into the web resolve
 * path). This module does NOT re-implement any of those checks -- it only
 * classifies the errors they throw into the UI-SPEC failure UX (toast type +
 * copy + action) and implements the one piece of behavior that belongs on
 * the web side: the bounded-backoff retry for a deferred mutation (D-06).
 *
 * `runWithFailureUx` wraps a single mutation call (the SDK client
 * invocation, not the surrounding hook logic -- callers stay thin wrappers
 * per RESEARCH.md Pitfall 1) and:
 *   - retries a `ReconcileStaleError` (SC#3/D-04) with bounded backoff,
 *     surfacing an info notice while retrying and a terminal, manually
 *     retryable error notice on exhaustion -- never a durable queue (D-06).
 *   - surfaces a `SequenceRegressionError`/`GenerationRegressionError`
 *     (D-05) immediately as a per-mutation error notice, no retry.
 *   - surfaces a stale/rotated-out write-descriptor failure (D-01/WRITE-03)
 *     with a one-tap re-resolve action, escalating to a terminal notice with
 *     no action if the re-resolve still fails.
 *   - surfaces the one-time degraded-cache notice (D-08) at most once per
 *     session, reading the 68-06 `rotation-state.service` flag.
 *
 * Every classified branch rethrows after dispatching its notice -- the
 * calling hook's existing catch/setState/logger path is unaffected; this
 * only augments the failure path with user-visible UX. Unclassified errors
 * pass through untouched.
 */

import {
  ReconcileStaleError,
  SequenceRegressionError,
  GenerationRegressionError,
  CannotWriteUntilRefetchError,
} from '@cipherbox/sdk';
import { useNotificationStore } from '../stores/notification.store';
import { isRotationStateDegraded } from '../services/rotation-state.service';

/**
 * Backoff schedule (ms) between retries of a `ReconcileStaleError` defer
 * (D-06). Four delays -> five total attempts (one initial + four retries),
 * summing to exactly 30s -- the "~5 attempts / ~30s" target from D-06.
 */
export const RECONCILE_RETRY_DELAYS_MS = [2000, 4000, 8000, 16000] as const;

export type RunWithFailureUxOptions = {
  /**
   * Re-resolves the write descriptor for a stale/rotated-out co-writer
   * write (D-01/WRITE-03) before a single automatic retry. Omit for
   * mutations that never touch a shared write descriptor -- those
   * immediately surface the terminal revoked notice instead.
   */
  refreshWriteAccess?: () => Promise<void>;
  /**
   * @internal Set on the retry issued after `refreshWriteAccess` runs, so a
   * second stale-write failure escalates straight to the terminal revoked
   * notice instead of re-offering the refresh action.
   */
  _afterRefresh?: boolean;
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

let degradedCacheWarningShown = false;

/** D-08: dispatches the degraded-cache notice at most once per session. */
function maybeWarnDegradedCache(): void {
  if (degradedCacheWarningShown || !isRotationStateDegraded()) return;
  degradedCacheWarningShown = true;
  useNotificationStore
    .getState()
    .addNotification('warning', 'Secure cache unavailable — falling back to server verification.');
}

/** D-06: dispatches the terminal defer-exhausted notice with a manual Retry action. */
function dispatchDeferExhausted<T>(mutationFn: () => Promise<T>): void {
  useNotificationStore.getState().addNotification('error', "Couldn't complete securely — retry.", {
    label: 'Retry',
    onClick: () => {
      void runWithFailureUx(mutationFn);
    },
  });
}

/**
 * Runs `mutationFn`, retrying only on `ReconcileStaleError` with the bounded
 * backoff schedule above. Any other error (including a `ReconcileStaleError`
 * exhaustion, which dispatches its own terminal notice here) is rethrown for
 * the outer classifier in `runWithFailureUx`.
 */
async function runReconcileRetryLoop<T>(mutationFn: () => Promise<T>): Promise<T> {
  let attempt = 0;
  let shownSyncingNotice = false;

  for (;;) {
    try {
      return await mutationFn();
    } catch (err) {
      if (!(err instanceof ReconcileStaleError)) throw err;

      if (attempt >= RECONCILE_RETRY_DELAYS_MS.length) {
        dispatchDeferExhausted(mutationFn);
        throw err;
      }

      if (!shownSyncingNotice) {
        shownSyncingNotice = true;
        useNotificationStore.getState().addNotification('info', 'Syncing latest state…');
      }

      await sleep(RECONCILE_RETRY_DELAYS_MS[attempt]);
      attempt += 1;
    }
  }
}

/** D-05: dispatches the regression-rejected notice. Never retried. */
function dispatchRegressionRejected(): void {
  useNotificationStore.getState().addNotification('error', 'Stale data from server rejected.');
}

/**
 * D-01/WRITE-03: dispatches either the re-resolvable stale-write notice (with
 * a `Refresh access` action) or, once a refresh has already been attempted
 * and still failed, the terminal revoked notice with no action.
 */
function dispatchWriteDescriptorStale<T>(
  mutationFn: () => Promise<T>,
  opts: RunWithFailureUxOptions
): void {
  if (opts.refreshWriteAccess && !opts._afterRefresh) {
    useNotificationStore
      .getState()
      .addNotification('error', 'Write failed — access may be out of date.', {
        label: 'Refresh access',
        onClick: () => {
          void retryAfterRefresh(mutationFn, opts);
        },
      });
  } else {
    useNotificationStore.getState().addNotification('error', 'Write access revoked.');
  }
}

async function retryAfterRefresh<T>(
  mutationFn: () => Promise<T>,
  opts: RunWithFailureUxOptions
): Promise<void> {
  try {
    await opts.refreshWriteAccess!();
    await runWithFailureUx(mutationFn, { ...opts, _afterRefresh: true });
  } catch {
    // The retried run (or the refresh itself) dispatches its own terminal notice.
  }
}

/**
 * Runs a single mutation call, classifying any fail-closed error thrown by
 * the SDK/resolve layer into the exact UI-SPEC notice + retry policy. See
 * the module doc comment for the full behavior per error class.
 */
export async function runWithFailureUx<T>(
  mutationFn: () => Promise<T>,
  opts: RunWithFailureUxOptions = {}
): Promise<T> {
  try {
    return await runReconcileRetryLoop(mutationFn);
  } catch (err) {
    if (err instanceof SequenceRegressionError || err instanceof GenerationRegressionError) {
      dispatchRegressionRejected();
      throw err;
    }
    if (err instanceof CannotWriteUntilRefetchError) {
      dispatchWriteDescriptorStale(mutationFn, opts);
      throw err;
    }
    throw err;
  } finally {
    maybeWarnDegradedCache();
  }
}
