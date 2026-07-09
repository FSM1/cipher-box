/**
 * Tests for rotation/scope.ts
 *
 * TDD RED phase — tests written before implementation (63-05 Task 1).
 *
 * SC#4 / ROT-02 gate: the zero-rotation invariant.
 * A private delete/move with no covering grant MUST trigger ZERO rotateReadFromNode
 * invocations and ZERO IPNS publishes beyond the parent relink. This test proves
 * that invariant via a vi.fn() rotate spy injected into maybeRotateOnScopeExit.
 *
 * Also tests:
 *   - hasCoveringGrant pure-function behaviour across all ancestry/grant-root combinations
 *   - Anti-malicious-relay cross-check: relay omits grant root, localGrantRecord covers → rotated
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  hasCoveringGrant,
  maybeRotateOnScopeExit,
  type CoverageParams,
  type ScopeExitDeps,
} from '../../rotation/scope';

// ---------------------------------------------------------------------------
// hasCoveringGrant — pure predicate
// ---------------------------------------------------------------------------

describe('hasCoveringGrant', () => {
  it('returns false when ancestry is empty', () => {
    const params: CoverageParams = {
      nodeAncestorIpnsNames: [],
      activeGrantRootIpnsNames: new Set(['k51/root-a']),
      localGrantRecord: null,
    };
    expect(hasCoveringGrant(params)).toBe(false);
  });

  it('returns false when neither relay set nor local record covers any ancestor', () => {
    const params: CoverageParams = {
      nodeAncestorIpnsNames: ['k51/node-x', 'k51/parent-y', 'k51/root-z'],
      activeGrantRootIpnsNames: new Set(['k51/other-root']),
      localGrantRecord: { shareRootIpnsName: 'k51/unrelated-root' },
    };
    expect(hasCoveringGrant(params)).toBe(false);
  });

  it('returns false when relay set is empty and localGrantRecord is null', () => {
    const params: CoverageParams = {
      nodeAncestorIpnsNames: ['k51/node-x', 'k51/parent-y'],
      activeGrantRootIpnsNames: new Set(),
      localGrantRecord: null,
    };
    expect(hasCoveringGrant(params)).toBe(false);
  });

  it('returns true when a non-root ancestor is in the active relay grant roots', () => {
    const params: CoverageParams = {
      nodeAncestorIpnsNames: ['k51/node-x', 'k51/shared-folder', 'k51/root-z'],
      activeGrantRootIpnsNames: new Set(['k51/shared-folder']),
      localGrantRecord: null,
    };
    expect(hasCoveringGrant(params)).toBe(true);
  });

  it('returns true when the node itself (first element) is a relay grant root', () => {
    const params: CoverageParams = {
      nodeAncestorIpnsNames: ['k51/node-x'],
      activeGrantRootIpnsNames: new Set(['k51/node-x']),
      localGrantRecord: null,
    };
    expect(hasCoveringGrant(params)).toBe(true);
  });

  it('returns true when the top-level root ancestor is in the relay grant roots', () => {
    const params: CoverageParams = {
      nodeAncestorIpnsNames: ['k51/leaf', 'k51/mid', 'k51/root-shared'],
      activeGrantRootIpnsNames: new Set(['k51/root-shared']),
      localGrantRecord: null,
    };
    expect(hasCoveringGrant(params)).toBe(true);
  });

  // §3.9 / T-63-17 anti-malicious-relay: relay omits the grant root,
  // but the client's own localGrantRecord covers an ancestor → still covered.
  it('returns true when relay omits grant root but localGrantRecord covers an ancestor', () => {
    const params: CoverageParams = {
      nodeAncestorIpnsNames: ['k51/leaf', 'k51/shared-folder', 'k51/root'],
      activeGrantRootIpnsNames: new Set(), // relay omits it (malicious or stale)
      localGrantRecord: { shareRootIpnsName: 'k51/shared-folder' },
    };
    expect(hasCoveringGrant(params)).toBe(true);
  });

  it('returns true when localGrantRecord.shareRootIpnsName is the leaf node itself', () => {
    const params: CoverageParams = {
      nodeAncestorIpnsNames: ['k51/file-node'],
      activeGrantRootIpnsNames: new Set(),
      localGrantRecord: { shareRootIpnsName: 'k51/file-node' },
    };
    expect(hasCoveringGrant(params)).toBe(true);
  });

  it('does NOT count localGrantRecord when its shareRootIpnsName is not in the ancestry', () => {
    const params: CoverageParams = {
      nodeAncestorIpnsNames: ['k51/node-a', 'k51/parent-b'],
      activeGrantRootIpnsNames: new Set(),
      localGrantRecord: { shareRootIpnsName: 'k51/unrelated-root' },
    };
    expect(hasCoveringGrant(params)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// maybeRotateOnScopeExit — gating composition
// ---------------------------------------------------------------------------

describe('maybeRotateOnScopeExit', () => {
  let rotateSpy: ReturnType<typeof vi.fn>;
  let deps: ScopeExitDeps;

  beforeEach(() => {
    rotateSpy = vi.fn().mockResolvedValue(undefined);
    deps = { rotate: rotateSpy };
  });

  // -------------------------------------------------------------------------
  // SC#4 / ROT-02: THE ZERO-ROTATION INVARIANT
  //
  // A private delete/move/rename with NO covering grant must:
  //   - call the injected rotate spy ZERO times
  //   - return 'no-rotation'
  //   - produce ZERO IPNS publishes beyond the parent relink
  // -------------------------------------------------------------------------
  it('SC#4 / ROT-02: private delete (empty activeGrantRoots, no localGrantRecord) triggers zero rotations', async () => {
    const params: CoverageParams = {
      nodeAncestorIpnsNames: ['k51/private-leaf', 'k51/private-folder', 'k51/vault-root'],
      activeGrantRootIpnsNames: new Set(), // no shares exist
      localGrantRecord: null, // this client holds no grant
    };

    const result = await maybeRotateOnScopeExit(params, deps);

    // THE INVARIANT: zero rotate invocations
    expect(rotateSpy).not.toHaveBeenCalled();
    expect(result).toBe('no-rotation');
  });

  it('SC#4 / ROT-02: private move (non-matching relay + non-matching local record) triggers zero rotations', async () => {
    const params: CoverageParams = {
      nodeAncestorIpnsNames: ['k51/moved-node', 'k51/src-folder'],
      activeGrantRootIpnsNames: new Set(['k51/other-shared-folder']), // share for a different subtree
      localGrantRecord: { shareRootIpnsName: 'k51/other-shared-folder' }, // grant on a different subtree
    };

    const result = await maybeRotateOnScopeExit(params, deps);

    expect(rotateSpy).not.toHaveBeenCalled();
    expect(result).toBe('no-rotation');
  });

  // -------------------------------------------------------------------------
  // Covered case: scope-exit → exactly one rotation invocation
  // -------------------------------------------------------------------------
  it('calls rotate exactly once and returns "rotated" when an ancestor is a relay grant root', async () => {
    const params: CoverageParams = {
      nodeAncestorIpnsNames: ['k51/deleted-node', 'k51/shared-folder', 'k51/root'],
      activeGrantRootIpnsNames: new Set(['k51/shared-folder']),
      localGrantRecord: null,
    };

    const result = await maybeRotateOnScopeExit(params, deps);

    expect(rotateSpy).toHaveBeenCalledTimes(1);
    expect(result).toBe('rotated');
  });

  it('calls rotate exactly once when the node itself is the relay grant root', async () => {
    const params: CoverageParams = {
      nodeAncestorIpnsNames: ['k51/deleted-node'],
      activeGrantRootIpnsNames: new Set(['k51/deleted-node']),
      localGrantRecord: null,
    };

    const result = await maybeRotateOnScopeExit(params, deps);

    expect(rotateSpy).toHaveBeenCalledTimes(1);
    expect(result).toBe('rotated');
  });

  // -------------------------------------------------------------------------
  // §3.9 / T-63-17 anti-malicious-relay cross-check
  //
  // Relay omits the grant root (malicious or stale) but the client's own
  // localGrantRecord covers the ancestor → rotation MUST still fire.
  // -------------------------------------------------------------------------
  it('T-63-17: relay omits grant root but localGrantRecord covers ancestor → still rotated', async () => {
    const params: CoverageParams = {
      nodeAncestorIpnsNames: ['k51/deleted-file', 'k51/shared-folder', 'k51/root'],
      activeGrantRootIpnsNames: new Set(), // relay maliciously omits 'k51/shared-folder'
      localGrantRecord: { shareRootIpnsName: 'k51/shared-folder' }, // client knows it owns this grant
    };

    const result = await maybeRotateOnScopeExit(params, deps);

    // Anti-malicious-relay: localGrantRecord is authoritative cross-check
    expect(rotateSpy).toHaveBeenCalledTimes(1);
    expect(result).toBe('rotated');
  });

  it('does not call rotate more than once per maybeRotateOnScopeExit call', async () => {
    const params: CoverageParams = {
      // Multiple ancestors are grant roots (e.g., nested shared folders)
      nodeAncestorIpnsNames: ['k51/leaf', 'k51/shared-sub', 'k51/shared-root'],
      activeGrantRootIpnsNames: new Set(['k51/shared-sub', 'k51/shared-root']),
      localGrantRecord: { shareRootIpnsName: 'k51/shared-root' },
    };

    const result = await maybeRotateOnScopeExit(params, deps);

    // ONE rotation per scope-exit, regardless of how many ancestors are grant roots
    expect(rotateSpy).toHaveBeenCalledTimes(1);
    expect(result).toBe('rotated');
  });
});
