import { describe, it, expect } from 'vitest';
import type { FolderChild, FolderEntry, FilePointer } from '@cipherbox/core';
import { renameInFolder, deleteFromFolder, addFilePointerToFolder, moveItem } from '../folder';

// These tests cover the pure (synchronous) folder metadata operations.
// async operations (loadFolderMetadata, updateFolderMetadataAndPublish, createSubfolder)
// require mocking IPFS/IPNS and are covered in integration tests.

const makeFolder = (id: string, name: string): FolderEntry => ({
  type: 'folder',
  id,
  name,
  ipnsName: `k51-${id}`,
  ipnsPrivateKeyEncrypted: 'encrypted-key',
  folderKeyEncrypted: 'encrypted-folder-key',
  createdAt: 1000,
  modifiedAt: 1000,
});

const makeFile = (id: string, name: string): FilePointer => ({
  type: 'file',
  id,
  name,
  fileMetaIpnsName: `k51-file-${id}`,
  ipnsPrivateKeyEncrypted: 'encrypted-key',
  createdAt: 1000,
  modifiedAt: 1000,
});

describe('Folder operations', () => {
  describe('renameInFolder', () => {
    it('renames a child and updates modifiedAt', () => {
      const children: FolderChild[] = [makeFolder('f1', 'Documents'), makeFile('f2', 'photo.jpg')];

      const result = renameInFolder({
        children,
        childId: 'f1',
        newName: 'My Documents',
      });

      expect(result.updatedChildren).toHaveLength(2);
      expect(result.renamedChild.name).toBe('My Documents');
      expect(result.renamedChild.modifiedAt).toBeGreaterThan(1000);
      // Original array not mutated
      expect(children[0].name).toBe('Documents');
    });

    it('throws when child not found', () => {
      const children: FolderChild[] = [makeFolder('f1', 'Documents')];

      expect(() => renameInFolder({ children, childId: 'nonexistent', newName: 'New' })).toThrow(
        'Item not found'
      );
    });

    it('throws on name collision', () => {
      const children: FolderChild[] = [makeFolder('f1', 'Documents'), makeFolder('f2', 'Photos')];

      expect(() => renameInFolder({ children, childId: 'f1', newName: 'Photos' })).toThrow(
        'An item with this name already exists'
      );
    });
  });

  describe('deleteFromFolder', () => {
    it('removes child and returns it', () => {
      const children: FolderChild[] = [
        makeFolder('f1', 'Documents'),
        makeFile('f2', 'photo.jpg'),
        makeFile('f3', 'video.mp4'),
      ];

      const result = deleteFromFolder({ children, childId: 'f2' });

      expect(result.updatedChildren).toHaveLength(2);
      expect(result.removedItem.id).toBe('f2');
      expect(result.removedItem.name).toBe('photo.jpg');
      expect(result.updatedChildren.find((c) => c.id === 'f2')).toBeUndefined();
    });

    it('throws when child not found', () => {
      const children: FolderChild[] = [makeFolder('f1', 'Documents')];

      expect(() => deleteFromFolder({ children, childId: 'missing' })).toThrow('Item not found');
    });
  });

  describe('addFilePointerToFolder', () => {
    it('adds file pointer to children', () => {
      const children: FolderChild[] = [makeFolder('f1', 'Documents')];

      const result = addFilePointerToFolder({
        children,
        fileId: 'file-1',
        fileName: 'readme.txt',
        fileMetaIpnsName: 'k51-file-meta',
        ipnsPrivateKeyEncrypted: 'wrapped-key',
      });

      expect(result.updatedChildren).toHaveLength(2);
      expect(result.filePointer.type).toBe('file');
      expect(result.filePointer.id).toBe('file-1');
      expect(result.filePointer.name).toBe('readme.txt');
      expect(result.filePointer.fileMetaIpnsName).toBe('k51-file-meta');
    });

    it('throws on name collision', () => {
      const children: FolderChild[] = [makeFile('f1', 'readme.txt')];

      expect(() =>
        addFilePointerToFolder({
          children,
          fileId: 'file-2',
          fileName: 'readme.txt',
          fileMetaIpnsName: 'k51-new',
          ipnsPrivateKeyEncrypted: 'key',
        })
      ).toThrow('A file with this name already exists');
    });
  });

  describe('moveItem', () => {
    it('moves item from source to destination', () => {
      const sourceChildren: FolderChild[] = [
        makeFolder('f1', 'Documents'),
        makeFile('f2', 'photo.jpg'),
      ];
      const destChildren: FolderChild[] = [makeFolder('f3', 'Archive')];

      const result = moveItem({
        sourceChildren,
        destChildren,
        childId: 'f2',
      });

      expect(result.updatedSourceChildren).toHaveLength(1);
      expect(result.updatedDestChildren).toHaveLength(2);
      expect(result.movedItem.name).toBe('photo.jpg');
      expect(result.movedItem.modifiedAt).toBeGreaterThan(1000);
    });

    it('throws when item not found in source', () => {
      expect(() =>
        moveItem({
          sourceChildren: [makeFolder('f1', 'Docs')],
          destChildren: [],
          childId: 'missing',
        })
      ).toThrow('Item not found');
    });

    it('throws on name collision in destination', () => {
      const sourceChildren: FolderChild[] = [makeFile('f1', 'readme.txt')];
      const destChildren: FolderChild[] = [makeFile('f2', 'readme.txt')];

      expect(() => moveItem({ sourceChildren, destChildren, childId: 'f1' })).toThrow(
        'An item with this name already exists in destination'
      );
    });
  });
});
