import { describe, it, expect } from 'vitest';
import type { SealedChildRef } from '@cipherbox/core';
import { ConflictError, isConflictExhausted, is409 } from '../errors';
import { mergeChildren } from '../folder/merge';

// These tests cover the pure (synchronous) ConflictError class and
// the mergeChildren three-way merge function.

// ---------------------------------------------------------------------------
// SealedChildRef factory helper
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
// ConflictError
// ---------------------------------------------------------------------------

describe('ConflictError', () => {
  it('carries ipnsName, attempts, lastRemoteSeq fields', () => {
    const err = new ConflictError('k51-abc', 4, 7n);
    expect(err.name).toBe('ConflictError');
    expect(err.ipnsName).toBe('k51-abc');
    expect(err.attempts).toBe(4);
    expect(err.lastRemoteSeq).toBe(7n);
    expect(err instanceof Error).toBe(true);
  });

  it('message contains ipnsName, attempts, and remote seq', () => {
    const err = new ConflictError('k51-abc', 4, 7n);
    expect(err.message).toContain('k51-abc');
    expect(err.message).toContain('4');
    expect(err.message).toContain('7');
  });

  it('message does NOT contain plaintext child data', () => {
    const err = new ConflictError('k51-abc', 4, 7n);
    // Only ipnsName + attempts + seq are safe to expose
    expect(err.message).not.toContain('child');
    expect(err.message).not.toContain('folder');
    expect(err.message).not.toContain('file');
  });

  it('isConflictExhausted returns true for ConflictError', () => {
    const err = new ConflictError('k51-abc', 4, 7n);
    expect(isConflictExhausted(err)).toBe(true);
  });

  it('isConflictExhausted returns false for plain Error', () => {
    expect(isConflictExhausted(new Error('other'))).toBe(false);
  });

  it('isConflictExhausted returns false for null', () => {
    expect(isConflictExhausted(null)).toBe(false);
  });

  it('isConflictExhausted returns false for plain object', () => {
    expect(isConflictExhausted({})).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// is409
// ---------------------------------------------------------------------------

describe('is409', () => {
  it('returns true for error with direct status 409', () => {
    expect(is409({ status: 409 })).toBe(true);
  });

  it('returns true for error with nested response.status 409', () => {
    expect(is409({ response: { status: 409 } })).toBe(true);
  });

  it('returns false for non-409 status', () => {
    expect(is409({ status: 500 })).toBe(false);
    expect(is409({ response: { status: 404 } })).toBe(false);
  });

  it('returns false for plain Error', () => {
    expect(is409(new Error('other'))).toBe(false);
  });

  it('returns false for null and undefined', () => {
    expect(is409(null)).toBe(false);
    expect(is409(undefined)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// mergeChildren — three-way SealedChildRef merge (ROT-05/HIGH-4)
// ---------------------------------------------------------------------------
// Semantics (design §3.7):
//   - Union by ipnsName: insert local, then remote (remote overwrites on conflict).
//   - Intentional delete: base entry absent from BOTH local AND remote is pruned.
//   - One-sided delete: base entry absent from only one side is kept (union wins).
// ---------------------------------------------------------------------------

describe('mergeChildren', () => {
  // Test 1: concurrent add (remote-only child) survives
  it('T1 concurrent add: child only in remote is present in result', () => {
    const a = makeChild('k51-A');
    const b = makeChild('k51-B');
    // base=[A], local=[A], remote=[A,B] — B is a concurrent add
    const result = mergeChildren([a], [a], [a, b]);
    const names = result.map((c) => c.ipnsName);
    expect(names).toContain('k51-A');
    expect(names).toContain('k51-B');
  });

  // Test 2: remote wins on conflict (same ipnsName, different variant)
  it('T2 remote wins on conflict: same ipnsName → remote variant in result', () => {
    const base = makeChild('k51-A', { generation: 1 });
    const local = makeChild('k51-A', { generation: 2, readKeySealed: 'local-sealed' });
    const remote = makeChild('k51-A', { generation: 2, readKeySealed: 'remote-sealed' });
    const result = mergeChildren([base], [local], [remote]);
    expect(result).toHaveLength(1);
    expect(result[0].readKeySealed).toBe('remote-sealed');
    expect(result[0]).toBe(remote);
  });

  // Test 3: intentional delete (absent from BOTH sides) is not resurrected
  it('T3 intentional delete: base entry absent from both local and remote is pruned', () => {
    const a = makeChild('k51-A');
    const c = makeChild('k51-C');
    // base=[A,C], local=[A] (C deleted locally), remote=[A] (C deleted remotely)
    const result = mergeChildren([a, c], [a], [a]);
    const names = result.map((r) => r.ipnsName);
    expect(names).toContain('k51-A');
    expect(names).not.toContain('k51-C');
    expect(result).toHaveLength(1);
  });

  // Test 4: one-sided delete is kept (union: local keeps it when only remote deleted)
  // Tie-break decision: union keeps the entry when at least one side still has it.
  it('T4 one-sided delete: base+local has C, remote deleted C — C survives (union keeps it)', () => {
    const a = makeChild('k51-A');
    const c = makeChild('k51-C');
    // base=[A,C], local=[A,C], remote=[A] — C deleted only by remote
    const result = mergeChildren([a, c], [a, c], [a]);
    const names = result.map((r) => r.ipnsName);
    expect(names).toContain('k51-A');
    expect(names).toContain('k51-C');
  });

  // Test 5: return type is SealedChildRef[]; does not throw
  it('T5 return type: mergeChildren returns SealedChildRef[] without throwing', () => {
    const a = makeChild('k51-A');
    let result: SealedChildRef[];
    expect(() => {
      result = mergeChildren([a], [a], [a]);
    }).not.toThrow();
    // The variable is assigned inside the expect callback; check it exists
    expect(Array.isArray(result!)).toBe(true);
  });

  // Immutability: input arrays are not mutated
  it('inputs not mutated: base/local/remote lengths unchanged after call', () => {
    const a = makeChild('k51-A');
    const c = makeChild('k51-C');
    const b = makeChild('k51-B');
    const base = [a, c];
    const local = [a, c];
    const remote = [a, b];
    mergeChildren(base, local, remote);
    expect(base).toHaveLength(2);
    expect(local).toHaveLength(2);
    expect(remote).toHaveLength(2);
  });
});
