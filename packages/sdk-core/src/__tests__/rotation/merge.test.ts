import { describe, it, expect } from 'vitest';
import type { SealedChildRef } from '@cipherbox/core';
import { mergeRotatedChildren } from '../../rotation/merge';

// ---------------------------------------------------------------------------
// SealedChildRef factory helper (mirrors folder-merge.test.ts's makeChild)
// ---------------------------------------------------------------------------

const makeChild = (ipnsName: string, overrides: Partial<SealedChildRef> = {}): SealedChildRef => ({
  name: ipnsName,
  ipnsName,
  generation: 0,
  versionFloor: 0n,
  readKeySealed: `sealed-${ipnsName}`,
  ...overrides,
});

// ---------------------------------------------------------------------------
// mergeRotatedChildren — rotation-only three-way merge, LOCAL WINS (SC#1)
// ---------------------------------------------------------------------------
// Semantics (70-PATTERNS.md / 70-RESEARCH.md Pattern 1):
//   - Local wins on conflict: preserves the rotation's D-02 re-seal so an
//     authorized reader stays navigable and a revoked reader's old-key seal
//     is never re-adopted.
//   - Remote-only (not-in-base) entries are concurrent adds: included, still
//     under their pre-rotation seal.
//   - Base-only (not in local AND not in remote) entries are intentional
//     deletes: dropped.
//   - Known accepted residual: a concurrent delete racing rotation is
//     resurrected by unconditional local-wins (RESEARCH Pitfall 2) — this is
//     documented, not fixed.
// ---------------------------------------------------------------------------

describe('mergeRotatedChildren', () => {
  it('local wins on conflict: same ipnsName in base+local+remote — result carries local readKeySealed (rotated new-key seal)', () => {
    const base = makeChild('k51-A', { readKeySealed: 'base-sealed' });
    const local = makeChild('k51-A', { readKeySealed: 'local-sealed-new-key' });
    const remote = makeChild('k51-A', { readKeySealed: 'remote-sealed-old-key' });

    const result = mergeRotatedChildren([base], [local], [remote]);

    expect(result).toHaveLength(1);
    expect(result[0].readKeySealed).toBe('local-sealed-new-key');
    expect(result[0]).toBe(local);
  });

  it('remote-only add is included: ipnsName present in remote but absent from base appears in result', () => {
    const a = makeChild('k51-A');
    const b = makeChild('k51-B');
    // base=[A], local=[A], remote=[A,B] — B is a concurrent add under its pre-rotation seal.
    const result = mergeRotatedChildren([a], [a], [a, b]);
    const names = result.map((c) => c.ipnsName);

    expect(names).toContain('k51-A');
    expect(names).toContain('k51-B');
    const bResult = result.find((c) => c.ipnsName === 'k51-B');
    expect(bResult).toBe(b);
  });

  it('base-only omission is dropped: ipnsName present in base but absent from BOTH local and remote is not resurrected', () => {
    const a = makeChild('k51-A');
    const c = makeChild('k51-C');
    // base=[A,C], local=[A] (C deleted locally), remote=[A] (C deleted remotely)
    const result = mergeRotatedChildren([a, c], [a], [a]);
    const names = result.map((r) => r.ipnsName);

    expect(names).toContain('k51-A');
    expect(names).not.toContain('k51-C');
    expect(result).toHaveLength(1);
  });

  // Documented residual (RESEARCH Pitfall 2 / T-70-02, accepted-low severity):
  // unconditional local-wins means a base+local entry with no corresponding
  // remote entry (a concurrent delete that raced the rotation) is NOT
  // pruned — it survives because local unconditionally overrides regardless
  // of remote's absence. This is intentionally NOT "fixed" here: the delete's
  // own later CAS retry, or the next owner mutation, self-heals it. Asserting
  // the KNOWN behavior below, not proposing a change.
  it('documented residual: concurrent delete during rotation is resurrected (accepted, self-healing — NOT a bug to fix here)', () => {
    const a = makeChild('k51-A');
    const c = makeChild('k51-C');
    // base=[A,C], local=[A,C] (rotation re-sealed both, unaware of the delete),
    // remote=[A] (C was concurrently deleted, raced the rotation's CAS).
    const result = mergeRotatedChildren([a, c], [a, c], [a]);
    const names = result.map((r) => r.ipnsName);

    // KNOWN behavior: C survives (local wins unconditionally) — this is the
    // accepted residual documented in T-70-02, not a defect.
    expect(names).toContain('k51-C');
  });
});
