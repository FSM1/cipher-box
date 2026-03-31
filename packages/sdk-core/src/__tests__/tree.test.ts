import { describe, it, expect } from 'vitest';
import { getDepth, isDescendantOf, calculateSubtreeDepth, type TreeNode } from '../folder/tree';

/*
 * Flat tree used across tests:
 *
 *   root (null parent)
 *   ├── a (depth 1)
 *   │   ├── b (depth 2)
 *   │   └── c (depth 2)
 *   │       └── d (depth 3)
 *   └── e (depth 1)
 */
const tree: Record<string, TreeNode> = {
  root: { id: 'root', parentId: null },
  a: { id: 'a', parentId: 'root' },
  b: { id: 'b', parentId: 'a' },
  c: { id: 'c', parentId: 'a' },
  d: { id: 'd', parentId: 'c' },
  e: { id: 'e', parentId: 'root' },
};

describe('getDepth', () => {
  it('returns 0 for null (root)', () => {
    expect(getDepth(null, tree)).toBe(0);
  });

  it('returns 0 for a node with null parentId', () => {
    expect(getDepth('root', tree)).toBe(0);
  });

  it('returns 1 for direct children of root', () => {
    expect(getDepth('a', tree)).toBe(1);
    expect(getDepth('e', tree)).toBe(1);
  });

  it('returns correct depth for nested nodes', () => {
    expect(getDepth('b', tree)).toBe(2);
    expect(getDepth('d', tree)).toBe(3);
  });

  it('returns 0 for unknown folder', () => {
    expect(getDepth('unknown', tree)).toBe(0);
  });
});

describe('isDescendantOf', () => {
  it('returns true for self', () => {
    expect(isDescendantOf('a', 'a', tree)).toBe(true);
  });

  it('returns true for direct child', () => {
    expect(isDescendantOf('b', 'a', tree)).toBe(true);
  });

  it('returns true for deeply nested descendant', () => {
    expect(isDescendantOf('d', 'root', tree)).toBe(true);
    expect(isDescendantOf('d', 'a', tree)).toBe(true);
  });

  it('returns false for non-descendant', () => {
    expect(isDescendantOf('e', 'a', tree)).toBe(false);
    expect(isDescendantOf('a', 'b', tree)).toBe(false);
  });

  it('returns false for unknown node', () => {
    expect(isDescendantOf('unknown', 'a', tree)).toBe(false);
  });
});

describe('calculateSubtreeDepth', () => {
  it('returns 0 for leaf node', () => {
    expect(calculateSubtreeDepth('d', tree)).toBe(0);
    expect(calculateSubtreeDepth('e', tree)).toBe(0);
  });

  it('returns 1 for node with only direct children', () => {
    expect(calculateSubtreeDepth('c', tree)).toBe(1);
  });

  it('returns max depth for node with mixed-depth children', () => {
    // a -> b (1), a -> c -> d (2)
    expect(calculateSubtreeDepth('a', tree)).toBe(2);
  });

  it('returns full tree depth for root', () => {
    // root -> a -> c -> d (3)
    expect(calculateSubtreeDepth('root', tree)).toBe(3);
  });

  it('returns 0 for unknown node', () => {
    expect(calculateSubtreeDepth('unknown', tree)).toBe(0);
  });
});
