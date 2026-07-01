/**
 * Multi-tab tail-walk leader election (D-09).
 *
 * First use of the Web Locks API (`navigator.locks`) in this codebase — no
 * existing analog to copy from (see 68-PATTERNS.md "No Analog Found").
 * Implemented directly against the MDN-documented `navigator.locks.request()`
 * contract: https://developer.mozilla.org/en-US/docs/Web/API/Web_Locks_API
 *
 * Elects a single tab to drive the rotation tail walk so concurrent tabs
 * don't race the same subtree's per-node CAS commits. `navigator.locks` is
 * secure-context-only and not universally supported — when it is absent
 * (older browser, insecure context), this falls back to running the
 * callback directly. That fallback is SAFE, not merely tolerated: the tail
 * walk is idempotent (per-node CAS commit + `completedNodeIds` skip) and any
 * lost CAS race re-merges via the concurrent-child-merge seam (design
 * §4.6/§4.7). A double-run only strengthens revocation — it never weakens it
 * (D-09 / Phase 64 D-07).
 */

const TAIL_WALK_LOCK_NAME = 'cipherbox-rotation-tail';

/**
 * Run `fn` under an exclusive named lock (`navigator.locks`) so only one tab
 * drives the rotation tail walk at a time.
 *
 * Falls back to invoking `fn` directly when `navigator.locks` is unavailable
 * (unsupported browser, insecure context, or non-browser environment) — both
 * tabs then run idempotently, which is safe per the module doc above.
 */
export async function withTailWalkLeader(fn: () => Promise<void>): Promise<void> {
  if (typeof navigator === 'undefined' || !navigator.locks) {
    await fn();
    return;
  }

  await navigator.locks.request(TAIL_WALK_LOCK_NAME, { mode: 'exclusive' }, async () => {
    await fn();
  });
}
