/**
 * Scope-exit predicate and gating helper for read-key rotation.
 *
 * Implements ROT-02 / SC#4 / design §3.6, §3.8, §3.9 (D-08).
 *
 * hasCoveringGrant: PURE predicate — no I/O, no durable state, no API calls.
 *   Takes the mutated node's ancestry chain, the relay-supplied active-grant-root
 *   set, and the client's own local grant record; returns true iff at least one
 *   ancestor (or the node itself) is a grant root.
 *
 * maybeRotateOnScopeExit: gating composition — rotate iff covered.
 *   Injects `deps.rotate` so callers can pass a vi.fn() spy in tests.
 *
 * @security
 *   T-63-17: The relay-supplied activeGrantRootIpnsNames is a COMPLETENESS AID,
 *   never the sole authority. A malicious relay can omit a grant root to suppress
 *   rotation — the client's own localGrantRecord is the anti-malicious-relay
 *   cross-check. Both sources are consulted; either one covering an ancestor is
 *   sufficient (§3.9).
 *
 * Coverage note (SC#5 / Pitfall 2):
 *   This file MUST remain `src/rotation/scope.ts` (named, not an index barrel).
 *   The sdk-core vitest config excludes `src/**\/index.ts` from coverage; a named
 *   file ensures hasCoveringGrant + maybeRotateOnScopeExit are counted.
 */

// ---------------------------------------------------------------------------
// Types — string-literal unions, never TypeScript enums (project convention)
// ---------------------------------------------------------------------------

/**
 * Inputs to the scope-exit coverage predicate (D-08).
 *
 * `nodeAncestorIpnsNames`   — IPNS k51 names of the mutated node and all its
 *    ancestors, ordered leaf-first (the node itself is first, vault root is last).
 *    The predicate checks all of them; the first match short-circuits.
 *
 * `activeGrantRootIpnsNames` — relay-supplied set of IPNS names that are known
 *    grant roots (from the API shares query). Treated as a COMPLETENESS AID:
 *    a relay can omit an entry to suppress rotation (T-63-17), so it is checked
 *    alongside localGrantRecord, not instead of it.
 *
 * `localGrantRecord` — the client's own record of a grant it holds on this
 *    node's ancestry. When non-null, localGrantRecord.shareRootIpnsName is the
 *    anti-malicious-relay cross-check (§3.9): if that IPNS name appears in
 *    the ancestry, the node is covered regardless of what the relay reports.
 */
export type CoverageParams = {
  nodeAncestorIpnsNames: string[];
  activeGrantRootIpnsNames: Set<string>;
  localGrantRecord: { shareRootIpnsName: string } | null;
};

/**
 * Result tag for maybeRotateOnScopeExit (string-literal union, no enum).
 *
 * `'no-rotation'` — no covering grant found; zero rotateReadFromNode invocations
 *    and zero IPNS publishes beyond the parent relink (ROT-02 / SC#4).
 * `'rotated'`     — a covering grant was found; deps.rotate was invoked once.
 */
export type ScopeExitResult = 'no-rotation' | 'rotated';

/**
 * Injectable dependencies for maybeRotateOnScopeExit (testability seam).
 *
 * `rotate` — the rotation function to invoke when hasCoveringGrant is true.
 *    In production this wraps a rotateReadFromNode call.
 *    In tests, pass a vi.fn() spy to assert call counts (the SC#4 zero-rotation
 *    invariant test relies on this injection point).
 */
export type ScopeExitDeps = {
  rotate: () => Promise<void>;
};

// ---------------------------------------------------------------------------
// hasCoveringGrant — pure predicate (D-08)
// ---------------------------------------------------------------------------

/**
 * Pure predicate: returns true iff the mutated node's ancestry contains a grant root.
 *
 * D-08: pure sdk-core function — no I/O, no durable state, no async.
 * §3.9: two independent sources are cross-checked:
 *   1. activeGrantRootIpnsNames (relay-supplied, completeness aid)
 *   2. localGrantRecord.shareRootIpnsName (client-authoritative, anti-malicious-relay)
 *
 * Either source covering any ancestor in nodeAncestorIpnsNames returns true.
 * Short-circuits at the first match to minimise work on hot delete/move/rename paths.
 *
 * @param params.nodeAncestorIpnsNames   — ancestry chain of the mutated node (incl. itself)
 * @param params.activeGrantRootIpnsNames — relay-supplied grant root set (completeness aid)
 * @param params.localGrantRecord        — client's own grant record (anti-malicious-relay check)
 *
 * @returns true iff coverage found; false → zero rotation, per ROT-02 / SC#4.
 *
 * @security No I/O. Never logs key material. Pure input→boolean transform.
 */
export function hasCoveringGrant(params: CoverageParams): boolean {
  const { nodeAncestorIpnsNames, activeGrantRootIpnsNames, localGrantRecord } = params;

  for (const ancestor of nodeAncestorIpnsNames) {
    // Check relay-supplied set (completeness aid — §3.9)
    if (activeGrantRootIpnsNames.has(ancestor)) {
      return true;
    }
    // Check client's own local grant record (anti-malicious-relay cross-check — §3.9 / T-63-17)
    if (localGrantRecord !== null && localGrantRecord.shareRootIpnsName === ancestor) {
      return true;
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// maybeRotateOnScopeExit — gating composition (§3.6, §3.8)
// ---------------------------------------------------------------------------

/**
 * Gating helper: compute hasCoveringGrant; rotate iff covered; return result tag.
 *
 * This is the single composition point for the §3.8 "one rule, four call sites"
 * policy. Every delete/move/rename call site passes its ancestry + grant-root
 * context here instead of inline-branching. The injectable `deps.rotate` allows
 * tests to assert call counts via a vi.fn() spy — the SC#4 zero-rotation invariant
 * test (the signature test for this phase) depends on that injection point.
 *
 * ROT-02 / SC#4 invariant:
 *   When hasCoveringGrant returns false, this function returns 'no-rotation' and
 *   NEVER invokes deps.rotate. Zero IPNS publishes beyond the parent relink.
 *   Proved by the scope.test.ts spy assertions.
 *
 * When hasCoveringGrant returns true, deps.rotate is invoked EXACTLY ONCE per
 * scope-exit event (one rotation per delete/move/rename regardless of how many
 * ancestors are grant roots).
 *
 * @param params — coverage inputs (ancestry + relay grant roots + local record)
 * @param deps   — injectable deps; deps.rotate wraps rotateReadFromNode in production
 *
 * @returns 'no-rotation' | 'rotated'
 *
 * @security No key material is held or zeroed here. Delegates zeroization to
 *   deps.rotate (the engine.ts rotateReadFromNode callee, which follows D-09).
 */
export async function maybeRotateOnScopeExit(
  params: CoverageParams,
  deps: ScopeExitDeps
): Promise<ScopeExitResult> {
  if (!hasCoveringGrant(params)) {
    // ROT-02 / SC#4: no covering grant → zero rotation, zero IPNS publishes.
    // The caller already performed the parent relink; no further action here.
    return 'no-rotation';
  }

  // Covered scope-exit: invoke rotation exactly once.
  // deps.rotate is injected for testability (vi.fn() spy in scope.test.ts).
  await deps.rotate();
  return 'rotated';
}
