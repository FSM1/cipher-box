import { describe, it, expect } from 'vitest';
import type { FolderChild, FolderEntry, FilePointer } from '@cipherbox/core';
import { ConflictError, isConflictExhausted, is409 } from '../errors';
import { mergeChildren } from '../folder/merge';

// These tests cover the pure (synchronous) ConflictError class and
// the mergeChildren three-way merge function.

const makeFolder = (id: string, name: string, modifiedAt = 1000): FolderEntry => ({
  type: 'folder',
  id,
  name,
  ipnsName: `k51-${id}`,
  ipnsPrivateKeyEncrypted: 'encrypted-key',
  folderKeyEncrypted: 'encrypted-folder-key',
  createdAt: 1000,
  modifiedAt,
});

const makeFile = (id: string, name: string, modifiedAt = 1000): FilePointer => ({
  type: 'file',
  id,
  name,
  fileMetaIpnsName: `k51-file-${id}`,
  ipnsPrivateKeyEncrypted: 'encrypted-key',
  createdAt: 1000,
  modifiedAt,
});

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

describe('mergeChildren', () => {
  it('local-add: child only in local is kept', () => {
    const localChild: FolderChild = makeFile('f1', 'local-only.txt');
    const result = mergeChildren([], [localChild], []);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe('f1');
  });

  it('remote-add: child only in remote is kept', () => {
    const remoteChild: FolderChild = makeFile('f2', 'remote-only.txt');
    const result = mergeChildren([], [], [remoteChild]);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe('f2');
  });

  it('added-by-both: last-write-wins by modifiedAt with >= preferring local on tie', () => {
    const local: FolderChild = makeFile('f3', 'both.txt', 2000);
    const remote: FolderChild = makeFile('f3', 'both-remote.txt', 1500);
    const result = mergeChildren([], [local], [remote]);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(local);
  });

  it('local-delete-dropped: child in base+remote but deleted locally is dropped when remote unchanged', () => {
    const base: FolderChild = makeFile('f4', 'deleted.txt', 1000);
    const remote: FolderChild = makeFile('f4', 'deleted.txt', 1000);
    const result = mergeChildren([base], [], [remote]);
    expect(result).toHaveLength(0);
  });

  it('edit-beats-delete: remote edit after base survives local delete', () => {
    const base: FolderChild = makeFile('f5', 'edited.txt', 1000);
    const remote: FolderChild = makeFile('f5', 'edited-remote.txt', 2000);
    const result = mergeChildren([base], [], [remote]);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(remote);
  });

  it('remote-delete-local-wins: child in base+local but deleted remotely keeps local', () => {
    const base: FolderChild = makeFile('f6', 'kept.txt', 1000);
    const local: FolderChild = makeFile('f6', 'kept.txt', 1000);
    const result = mergeChildren([base], [local], []);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(local);
  });

  it('modified-in-both: last-write-wins by modifiedAt', () => {
    const base: FolderChild = makeFile('f7', 'modified.txt', 1000);
    const local: FolderChild = makeFile('f7', 'modified-local.txt', 3000);
    const remote: FolderChild = makeFile('f7', 'modified-remote.txt', 2000);
    const result = mergeChildren([base], [local], [remote]);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(local);
  });

  it('D-02 union fallback: empty base returns union of local and remote', () => {
    const l1: FolderChild = makeFile('f8', 'local.txt');
    const r1: FolderChild = makeFile('f9', 'remote.txt');
    const result = mergeChildren([], [l1], [r1]);
    expect(result).toHaveLength(2);
    const ids = result.map((c) => c.id);
    expect(ids).toContain('f8');
    expect(ids).toContain('f9');
  });

  it('missing-modifiedAt-defaults-0: undefined modifiedAt treated as 0', () => {
    const local = {
      ...makeFile('f10', 'no-ts.txt'),
      modifiedAt: undefined,
    } as unknown as FolderChild;
    const remote: FolderChild = makeFile('f10', 'remote.txt', 500);
    const result = mergeChildren([], [local], [remote]);
    // remote has higher modifiedAt (500 > 0), so remote wins
    expect(result).toHaveLength(1);
    expect((result[0] as FilePointer).name).toBe('remote.txt');
  });

  it('input-not-mutated: original arrays unchanged after call', () => {
    const base: FolderChild[] = [makeFile('f11', 'orig.txt', 1000)];
    const local: FolderChild[] = [makeFile('f11', 'local.txt', 2000)];
    const remote: FolderChild[] = [makeFile('f11', 'remote.txt', 1500)];
    const baseCopy = [...base];
    const localCopy = [...local];
    const remoteCopy = [...remote];
    mergeChildren(base, local, remote);
    expect(base).toEqual(baseCopy);
    expect(local).toEqual(localCopy);
    expect(remote).toEqual(remoteCopy);
  });

  it('combines local and remote adds with existing base children', () => {
    const baseChild: FolderChild = makeFolder('d1', 'Docs');
    const localAdd: FolderChild = makeFile('f12', 'local-add.txt');
    const remoteAdd: FolderChild = makeFile('f13', 'remote-add.txt');
    const result = mergeChildren([baseChild], [baseChild, localAdd], [baseChild, remoteAdd]);
    expect(result).toHaveLength(3);
    const ids = result.map((c) => c.id);
    expect(ids).toContain('d1');
    expect(ids).toContain('f12');
    expect(ids).toContain('f13');
  });
});
