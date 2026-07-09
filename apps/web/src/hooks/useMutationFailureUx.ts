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
 *   - retries a `ReconcileStaleError` whose network sequence is AHEAD of the
 *     local one (SC#3/D-04, a genuine concurrent update elsewhere) with
 *     bounded backoff, surfacing an info notice while retrying and a
 *     terminal, manually retryable error notice on exhaustion -- never a
 *     durable queue (D-06).
 *   - surfaces a `SequenceRegressionError`/`GenerationRegressionError`, or a
 *     `ReconcileStaleError` whose network sequence is BEHIND the local one
 *     (a stale/relay-replayed record the durable ROT-07 floor may not catch
 *     when the replayed seq exactly matches its last-recorded floor -- Gap 4
 *     / 68.1-21), (D-05) immediately as a per-mutation error notice, no
 *     retry.
 *   - surfaces a stale/rotated-out write-encrypted-key failure (D-01/WRITE-03)
 *     with a one-tap re-resolve action, escalating to a terminal notice with
 *     no action if the re-resolve still fails.
 *   - surfaces the one-time degraded-cache notice (D-08) at most once per
 *     session, reading the 68-06 `rotation-state.service` flag.
 *
 * Every classified branch rethrows after dispatching its notice -- the
 * calling hook's existing catch/setState/logger path is unaffected; this
 * only augments the failure path with user-visible UX. Unclassified errors
 * pass through untouched.
 *
 * 68.1-28 diagnostic note (rotation-durability.spec.ts SC-4 residual): the
 * classification above is verified correct and complete for every error
 * class `client.ts`'s `reconcileFolderSequence`/`rotationHighWater.
 * enforceResolved` can throw. SC-4's residual failure is NOT a gap in this
 * module -- a live repro confirmed the rename mutation SUCCEEDS silently
 * (no error of any kind is thrown), because `apps/api`'s IPNS resolve
 * prefers the DB-cached record whenever it is at or ahead of the network
 * record (`ipns.service.ts::resolveRecord`), and the DB row is written
 * synchronously on every publish this same client makes. A relay-replayed
 * record captured from an earlier point in this client's own history can
 * therefore never be strictly ahead of that client's own DB row, so the
 * replay never reaches this classifier (or `enforceResolved`) to begin
 * with. See 68.1-28-SUMMARY.md for the full trace and the follow-up this
 * surfaces -- do not re-attempt a classification fix here without first
 * reading that finding.
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
   * Re-resolves the write encrypted key for a stale/rotated-out co-writer
   * write (D-01/WRITE-03) before a single automatic retry. Omit for
   * mutations that never touch a shared write encrypted key -- those
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
function dispatchDeferExhausted<T>(
  mutationFn: () => Promise<T>,
  opts: RunWithFailureUxOptions
): void {
  const id = useNotificationStore
    .getState()
    .addNotification('error', "Couldn't complete securely — retry.", {
      label: 'Retry',
      onClick: () => {
        // Replace, don't stack: a persistent failure re-dispatches a fresh
        // exhaustion toast, so drop this one before re-running.
        useNotificationStore.getState().dismissNotification(id);
        void retryAfterExhaustion(mutationFn, opts);
      },
    });
}

async function retryAfterExhaustion<T>(
  mutationFn: () => Promise<T>,
  opts: RunWithFailureUxOptions
): Promise<void> {
  try {
    // Thread the ORIGINAL opts through the manual retry so a subsequent
    // stale-write failure still offers the refreshWriteAccess path.
    await runWithFailureUx(mutationFn, opts);
  } catch {
    // The retried run dispatches its own notice for any repeat failure.
  }
}

/**
 * Runs `mutationFn`, retrying only on `ReconcileStaleError` with the bounded
 * backoff schedule above. Any other error (including a `ReconcileStaleError`
 * exhaustion, which dispatches its own terminal notice here) is rethrown for
 * the outer classifier in `runWithFailureUx`.
 */
async function runReconcileRetryLoop<T>(
  mutationFn: () => Promise<T>,
  opts: RunWithFailureUxOptions
): Promise<T> {
  let attempt = 0;
  let shownSyncingNotice = false;

  for (;;) {
    try {
      return await mutationFn();
    } catch (err) {
      if (!(err instanceof ReconcileStaleError)) throw err;

      // A ReconcileStaleError with the network sequence BEHIND the local one
      // is not a legitimate defer-and-retry (D-04) scenario -- it means the
      // resolve returned a record older than what this client already knows
      // to be true, i.e. a stale/relay-replayed record (T-68-101). The
      // durable ROT-07 floor (rotation-high-water.ts) only rejects a resolve
      // BELOW its last-recorded floor; a replay that exactly matches the
      // floor (because the floor is only bumped pre-publish, one step behind
      // this client's own already-published state) sails through that gate
      // and lands here instead. Reject it immediately, fail-closed, via the
      // outer D-05 classifier -- never retry a rollback.
      if (err.networkSequence < err.localSequence) throw err;

      if (attempt >= RECONCILE_RETRY_DELAYS_MS.length) {
        dispatchDeferExhausted(mutationFn, opts);
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
function dispatchEncryptedWriteKeyStale<T>(
  mutationFn: () => Promise<T>,
  opts: RunWithFailureUxOptions
): void {
  if (opts.refreshWriteAccess && !opts._afterRefresh) {
    const id = useNotificationStore
      .getState()
      .addNotification('error', 'Write failed — access may be out of date.', {
        label: 'Refresh access',
        onClick: () => {
          // Replace, don't stack: the refresh/retry path dispatches its own
          // follow-up notice, so drop this one before re-running (same
          // anti-stacking rule as the defer-exhausted Retry above).
          useNotificationStore.getState().dismissNotification(id);
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
  } catch {
    useNotificationStore
      .getState()
      .addNotification('error', 'Write access could not be refreshed.');
    return;
  }
  try {
    await runWithFailureUx(mutationFn, { ...opts, _afterRefresh: true });
  } catch {
    // The retried run dispatches its own terminal notice.
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
    return await runReconcileRetryLoop(mutationFn, opts);
  } catch (err) {
    if (
      err instanceof SequenceRegressionError ||
      err instanceof GenerationRegressionError ||
      // A ReconcileStaleError reaches here (rather than being retried by
      // runReconcileRetryLoop) only when its networkSequence is BEHIND its
      // localSequence -- see that loop's early-rethrow. That direction is a
      // stale/relay-replayed record, not a legitimate concurrent-update
      // defer, so it gets the same immediate D-05 rejection notice.
      (err instanceof ReconcileStaleError && err.networkSequence < err.localSequence)
    ) {
      dispatchRegressionRejected();
      throw err;
    }
    if (err instanceof CannotWriteUntilRefetchError) {
      dispatchEncryptedWriteKeyStale(mutationFn, opts);
      throw err;
    }
    throw err;
  } finally {
    maybeWarnDegradedCache();
  }
}
