import { describe, expect, it } from 'vitest';
import { folderPath, folderRoute, sameNode } from './nodeId';

const NODE = new Uint8Array(16).fill(0xab);

describe('folderRoute', () => {
  it('reads an absent param as the vault root', () => {
    expect(folderRoute(undefined)).toEqual({ kind: 'root' });
  });

  it('round-trips a node id through its route', () => {
    const route = folderRoute(folderPath(NODE).replace('/files/', ''));
    expect(route).toEqual({ kind: 'node', id: NODE });
  });

  it.each([
    ['too short', 'ab'],
    ['too long', 'ab'.repeat(17)],
    ['not hex', 'zz'.repeat(16)],
    ['empty', ''],
  ])('rejects a param that is %s', (_case, param) => {
    expect(folderRoute(param)).toEqual({ kind: 'invalid' });
  });
});

describe('folderPath', () => {
  it('addresses the current root without a node id', () => {
    expect(folderPath(null)).toBe('/files');
  });

  it('addresses a node by lowercase hex', () => {
    expect(folderPath(NODE)).toBe(`/files/${'ab'.repeat(16)}`);
  });
});

describe('sameNode', () => {
  it('compares by value, not identity', () => {
    expect(sameNode(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(sameNode(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(sameNode(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });

  it('treats null as the root, matching only itself', () => {
    expect(sameNode(null, null)).toBe(true);
    expect(sameNode(null, new Uint8Array([1]))).toBe(false);
  });
});
