/**
 * Rotation Driver — concrete web callbacks for the SDK's scope-exit rotation
 * injection seam (68-05) + D-02/D-03 progress-badge wiring + D-09 multi-tab
 * leader election + resumable durable job checkpoint.
 *
 * THIN, UNTESTED glue (per docs/TESTING.md doctrine): all monotonic-max /
 * idempotency / CAS-409 re-merge logic lives in the SDK (68-01/63/64) and is
 * unit-proven there. This module only maps rotation lifecycle signals onto
 * the web's durable IndexedDB checkpoint + the `rotation.store` badge + the
 * `multi-tab-lock` leader election. Proven end-to-end (badge lifecycle +
 * resume-after-reload) by the 68-10 web-e2e rotation-ux spec.
 *
 * @security
 * `persistJob` NEVER serialises key material (Pitfall 4 / T-68-83): it
 * writes only `rootNodeId`, `status`, `completedNodeIds`, and the frontier's
 * `nodeIpnsName`s to IndexedDB — never `parentReadKey`/`ipnsPrivateKey`
 * bytes. It also never zeros/mutates the caller's `RotationJobRecord`
 * buffers — this callback is a read-only observer, not a terminal key owner
 * (D-09; see `rotation/engine.ts`'s zeroization docblocks).
 *
 * @security
 * Badge lifecycle timing note: the SDK chokepoint (`performScopeExitRotation`
 * in `packages/sdk/src/client.ts`) awaits the ENTIRE rotation (root cut +
 * tail walk) before the triggering mutation resolves — there is no separate
 * "root cut is starting" hook exposed today. `rotateReadFromNode` DOES call
 * `persistCallback` (this module's `persistJob`) as its first checkpoint
 * immediately after the root commits (the "high-value early checkpoint"),
 * and again after every subsequent per-node tail commit, and finally once
 * more with `status: 'complete'`. This module therefore treats the FIRST
 * `persistJob` call for a given `rootNodeId` as the root-cut signal
 * (`beginRootCut`) and every SUBSEQUENT call for the same root as tail-walk
 * progress (`beginTailWalk`), before resetting on the terminal call.
 */

import type { RotationClientCallbacks, LocalGrantRecord } from '@cipherbox/sdk';
import type { RotationJobRecord } from '@cipherbox/sdk-core';
import { useShareStore } from '../stores/share.store';
import { useRotationStore } from '../stores/rotation.store';
import { withTailWalkLeader } from '../lib/multi-tab-lock';
import { logger } from '../lib/logger';

// ---------------------------------------------------------------------------
// Durable job checkpoint (metadata-only — never key material, Pitfall 4)
// ---------------------------------------------------------------------------

const JOB_DB_NAME = 'cipherbox-rotation-jobs';
const JOB_DB_VERSION = 1;
const JOB_STORE_NAME = 'jobs';

/** Sanitized, durable projection of a `RotationJobRecord` — metadata only, NEVER key bytes. */
type DurableJobCheckpoint = {
  rootNodeId: string;
  status: RotationJobRecord['status'];
  completedNodeIds: string[];
  frontierIpnsNames: string[];
  updatedAt: number;
};

function openJobDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(JOB_DB_NAME, JOB_DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(JOB_STORE_NAME)) {
        db.createObjectStore(JOB_STORE_NAME, { keyPath: 'rootNodeId' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function putJobCheckpoint(checkpoint: DurableJobCheckpoint): Promise<void> {
  const db = await openJobDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(JOB_STORE_NAME, 'readwrite');
    tx.objectStore(JOB_STORE_NAME).put(checkpoint);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function deleteJobCheckpoint(rootNodeId: string): Promise<void> {
  const db = await openJobDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(JOB_STORE_NAME, 'readwrite');
    tx.objectStore(JOB_STORE_NAME).delete(rootNodeId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function getAllJobCheckpoints(): Promise<DurableJobCheckpoint[]> {
  const db = await openJobDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(JOB_STORE_NAME, 'readonly');
    const request = tx.objectStore(JOB_STORE_NAME).getAll();
    request.onsuccess = () => resolve((request.result ?? []) as DurableJobCheckpoint[]);
    request.onerror = () => reject(request.error);
  });
}

// ---------------------------------------------------------------------------
// Badge-lifecycle state (D-02/D-03)
// ---------------------------------------------------------------------------

/**
 * The root currently driving the badge, so a later `persistJob` call for the
 * SAME root is recognised as tail-walk progress rather than a fresh root cut.
 */
let activeRootNodeId: string | null = null;

const TERMINAL_STATUSES: ReadonlySet<RotationJobRecord['status']> = new Set(['complete', 'failed']);

/**
 * Durable job-checkpoint + badge-lifecycle persist callback.
 *
 * @security Metadata only (Pitfall 4) — never serialises `frontier[].parentReadKey`
 * / `ipnsPrivateKey` bytes, and never zeros/mutates `job`'s buffers (D-09: this
 * callback is a read-only observer, not a terminal key owner).
 */
async function persistJob(job: RotationJobRecord): Promise<void> {
  if (TERMINAL_STATUSES.has(job.status)) {
    // Rotation finished (or failed) for this root — published IPNS records are
    // the source of truth from here (D-10); the durable checkpoint is only
    // useful while the walk is in flight, so drop it and reset the badge.
    activeRootNodeId = null;
    useRotationStore.getState().reset();
    try {
      await deleteJobCheckpoint(job.rootNodeId);
    } catch (error) {
      logger.error('[rotation-driver] Failed to clear durable job checkpoint:', error);
    }
    return;
  }

  if (activeRootNodeId !== job.rootNodeId) {
    // First non-terminal persistJob call for this root: fired immediately
    // after the root commits (the engine's "high-value early checkpoint") —
    // treat this as the root-cut signal (see module doc security note).
    activeRootNodeId = job.rootNodeId;
    useRotationStore.getState().beginRootCut();
  } else {
    // Subsequent calls for the same root are per-node tail-walk commits.
    useRotationStore.getState().beginTailWalk();
  }

  const checkpoint: DurableJobCheckpoint = {
    rootNodeId: job.rootNodeId,
    status: job.status,
    completedNodeIds: [...job.completedNodeIds],
    frontierIpnsNames: job.frontier.map((entry) => entry.nodeIpnsName),
    updatedAt: Date.now(),
  };

  try {
    await putJobCheckpoint(checkpoint);
  } catch (error) {
    // Best-effort durability: published IPNS records remain the source of
    // truth (D-10) — a failed checkpoint write only degrades resumability,
    // never correctness.
    logger.error('[rotation-driver] Failed to persist durable job checkpoint:', error);
  }
}

/**
 * Optional progress/status hook (D-02/D-03 badge). The current SDK chokepoint
 * only ever calls this once, with `'rotated'`, right after a rotation fully
 * completes (see `performScopeExitRotation` in `packages/sdk/src/client.ts`).
 * The `'root-cut'`/`'tail-walk'` cases are forward-compatible no-ops today
 * (those transitions are driven by `persistJob` — see module doc) and are
 * wired here so this driver requires no changes if the SDK chokepoint later
 * emits them directly.
 */
function progress(status: string): void {
  switch (status) {
    case 'root-cut':
      useRotationStore.getState().beginRootCut();
      break;
    case 'tail-walk':
      useRotationStore.getState().beginTailWalk();
      break;
    case 'rotated':
    case 'complete':
      activeRootNodeId = null;
      useRotationStore.getState().reset();
      break;
    default:
      // Unknown/forward-compatible status string — no-op.
      break;
  }
}

// ---------------------------------------------------------------------------
// Grant getters (anti-malicious-relay cross-check) — sourced from the loaded
// shares (68-02) grant state, never the relay's own claim.
// ---------------------------------------------------------------------------

function getActiveGrantRootIpnsNames(): Promise<Set<string>> {
  const { sentShares } = useShareStore.getState();
  return Promise.resolve(new Set(sentShares.map((share) => share.ipnsName)));
}

function getLocalGrantRecord(ipnsName: string): LocalGrantRecord | null {
  const { sentShares } = useShareStore.getState();
  const isKnownGrantRoot = sentShares.some((share) => share.ipnsName === ipnsName);
  return isKnownGrantRoot ? { rootIpnsName: ipnsName } : null;
}

/**
 * Build the concrete `RotationClientCallbacks` injected into `CipherBoxClient`
 * at construction (`useAuth.ts`).
 */
export function buildRotationClientCallbacks(): RotationClientCallbacks {
  return {
    getActiveGrantRootIpnsNames,
    getLocalGrantRecord,
    persistJob,
    progress,
  };
}

// ---------------------------------------------------------------------------
// Resume-on-load (D-02/D-03 'resuming' badge state)
// ---------------------------------------------------------------------------

/**
 * On app load, check the durable store for an in-progress rotation job left
 * over from a previous session/reload and, if found, surface the 'resuming'
 * badge state.
 *
 * @remarks
 * A true replay of a partial walk (re-driving `rotateReadFromNode` from the
 * durable `completedNodeIds`) requires the SDK-core engine to accept a
 * pre-seeded job record, which it does not yet do — every mutation call
 * builds a fresh, empty `RotationJobRecord` (see `performScopeExitRotation`).
 * This is a known, already-flagged gap (see sdk-core `verifySubtreeClean`'s
 * doc comment and the `rotation-fresh-record-resume-and-sc4-double-bump`
 * todo), not something this thin web adapter can close on its own without an
 * SDK-side change. Published IPNS records remain the source of truth (D-10):
 * the subtree is never left insecure by this gap, only the LOCAL "resuming"
 * badge lingers until the next genuine mutation on that subtree naturally
 * re-triggers a fresh, idempotent rotation. The checkpoint is left in place
 * (not deleted) so a future SDK resume entrypoint can consume it.
 */
export async function resumeInterruptedRotation(): Promise<void> {
  let checkpoints: DurableJobCheckpoint[];
  try {
    checkpoints = await getAllJobCheckpoints();
  } catch (error) {
    logger.error('[rotation-driver] Failed to read durable job checkpoints on load:', error);
    return;
  }

  const inProgress = checkpoints.filter((checkpoint) => !TERMINAL_STATUSES.has(checkpoint.status));
  if (inProgress.length === 0) return;

  activeRootNodeId = inProgress[0].rootNodeId;
  useRotationStore.getState().markResuming();

  // Run under the tail-walk leader lock so a multi-tab reload doesn't race
  // this resume check (D-09) — see the @remarks above for why this cannot
  // yet replay the walk itself.
  await withTailWalkLeader(async () => {
    logger.info(
      `[rotation-driver] Found ${inProgress.length} interrupted rotation job(s) on load; badge set to resuming.`
    );
  });
}
