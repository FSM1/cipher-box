import { describe, it, expect } from 'vitest';
import { getDepth, calculateSubtreeDepth, isDescendantOf, type TreeNode } from '../tree';

/**
 * Build a folder map from a simple parent-child list.
 * Each entry: [id, parentId | null]
 */
function buildTree(entries: [string, string | null][]): Record<string, TreeNode> {
  const map: Record<string, TreeNode> = {};
  for (const [id, parentId] of entries) {
    map[id] = { id, parentId };
  }
  return map;
}

describe('tree utilities', () => {
  // Tree structure used in most tests:
  //   root (null parent)
  //     ├── a
  //     │   ├── b
  //     │   │   └── d
  //     │   └── c
  //     └── e
  const tree = buildTree([
    ['root', null],
    ['a', 'root'],
    ['b', 'a'],
    ['c', 'a'],
    ['d', 'b'],
    ['e', 'root'],
  ]);

  describe('getDepth', () => {
    it('returns 0 for null folderId (root)', () => {
      expect(getDepth(null, tree)).toBe(0);
    });

    it('returns 0 for a node with no parent (top-level root)', () => {
      expect(getDepth('root', tree)).toBe(0);
    });

    it('returns 1 for immediate child of root', () => {
      expect(getDepth('a', tree)).toBe(1);
    });

    it('returns 2 for grandchild of root', () => {
      expect(getDepth('b', tree)).toBe(2);
    });

    it('returns correct depth for deeply nested node', () => {
      expect(getDepth('d', tree)).toBe(3);
    });

    it('returns 0 for a folderId not in the map', () => {
      expect(getDepth('nonexistent', tree)).toBe(0);
    });

    it('returns 0 for an empty folder map', () => {
      expect(getDepth('a', {})).toBe(0);
    });

    it('handles chain broken by missing intermediate node', () => {
      // b's parent 'a' is missing -- traversal stops at b
      const broken = buildTree([
        ['root', null],
        ['b', 'a'],
      ]);
      // 'a' is not in the map, so walking up from b -> a (missing) -> stops
      expect(getDepth('b', broken)).toBe(1);
    });
  });

  describe('calculateSubtreeDepth', () => {
    it('returns 0 for a leaf node (no children)', () => {
      expect(calculateSubtreeDepth('d', tree)).toBe(0);
      expect(calculateSubtreeDepth('c', tree)).toBe(0);
      expect(calculateSubtreeDepth('e', tree)).toBe(0);
    });

    it('returns 1 for a node with only immediate children', () => {
      // 'b' has one child 'd' at depth 1
      expect(calculateSubtreeDepth('b', tree)).toBe(1);
    });

    it('returns correct depth for a subtree with mixed depths', () => {
      // 'a' has children: b (depth 1), c (depth 1), d (depth 2 via b)
      expect(calculateSubtreeDepth('a', tree)).toBe(2);
    });

    it('returns correct depth for root of entire tree', () => {
      // root -> a -> b -> d  = depth 3
      expect(calculateSubtreeDepth('root', tree)).toBe(3);
    });

    it('returns 0 for a node not in the map', () => {
      expect(calculateSubtreeDepth('nonexistent', tree)).toBe(0);
    });

    it('returns 0 for empty folder map', () => {
      expect(calculateSubtreeDepth('root', {})).toBe(0);
    });
  });

  describe('isDescendantOf', () => {
    it('returns true for direct child', () => {
      expect(isDescendantOf('a', 'root', tree)).toBe(true);
    });

    it('returns true for grandchild', () => {
      expect(isDescendantOf('b', 'root', tree)).toBe(true);
    });

    it('returns true for deeply nested descendant', () => {
      expect(isDescendantOf('d', 'root', tree)).toBe(true);
      expect(isDescendantOf('d', 'a', tree)).toBe(true);
    });

    it('returns false when child is not a descendant', () => {
      expect(isDescendantOf('e', 'a', tree)).toBe(false);
    });

    it('returns true when child and ancestor are the same node', () => {
      expect(isDescendantOf('a', 'a', tree)).toBe(true);
    });

    it('returns false when childId is not in the map', () => {
      expect(isDescendantOf('nonexistent', 'root', tree)).toBe(false);
    });

    it('returns false when ancestorId is not in the map', () => {
      expect(isDescendantOf('a', 'nonexistent', tree)).toBe(false);
    });

    it('returns false for reverse relationship (ancestor as child)', () => {
      expect(isDescendantOf('root', 'a', tree)).toBe(false);
    });

    it('returns false for siblings', () => {
      expect(isDescendantOf('a', 'e', tree)).toBe(false);
      expect(isDescendantOf('b', 'c', tree)).toBe(false);
    });

    it('handles broken chain (missing intermediate parent)', () => {
      const broken = buildTree([
        ['root', null],
        ['child', 'missing'],
      ]);
      // 'missing' is not in the map -- traversal stops, never finds 'root'
      expect(isDescendantOf('child', 'root', broken)).toBe(false);
    });
  });
});
