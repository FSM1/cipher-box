/**
 * Logout Security Tests
 *
 * Tests for ensuring cryptographic keys are properly cleared from memory on logout.
 * These tests verify the security requirements from the Phase 5 security review.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { useVaultStore } from '../vault.store';
import { useFolderStore, type FolderNode } from '../folder.store';

describe('Logout Security', () => {
  beforeEach(() => {
    // Reset stores before each test
    useVaultStore.setState({
      rootFolderKey: null,
      rootIpnsKeypair: null,
      rootIpnsName: null,
      vaultId: null,
      isInitialized: false,
    });

    useFolderStore.setState({
      folders: {},
      currentFolderId: null,
      breadcrumbs: [],
      pendingPublishes: new Set<string>(),
    });
  });

  describe('useVaultStore.clearVaultKeys', () => {
    it('should zero-fill vault keys on clearVaultKeys', () => {
      // Setup: Create mock keys with known values
      const rootFolderKey = new Uint8Array(32).fill(0xaa);
      const publicKey = new Uint8Array(32).fill(0xbb);
      const privateKey = new Uint8Array(32).fill(0xcc);

      // Keep references to check after clearing
      const keyReferences = {
        rootFolderKey,
        publicKey,
        privateKey,
      };

      // Initialize vault with keys
      useVaultStore.getState().setVaultKeys({
        rootFolderKey,
        rootIpnsKeypair: { publicKey, privateKey },
        rootIpnsName: 'k51qzi5uqu5test',
        vaultId: 'test-vault-id',
      });

      // Verify keys are set
      const stateBefore = useVaultStore.getState();
      expect(stateBefore.rootFolderKey).not.toBeNull();
      expect(stateBefore.rootIpnsKeypair).not.toBeNull();

      // Clear vault keys
      useVaultStore.getState().clearVaultKeys();

      // Verify state is cleared
      const stateAfter = useVaultStore.getState();
      expect(stateAfter.rootFolderKey).toBeNull();
      expect(stateAfter.rootIpnsKeypair).toBeNull();
      expect(stateAfter.rootIpnsName).toBeNull();
      expect(stateAfter.vaultId).toBeNull();
      expect(stateAfter.isInitialized).toBe(false);

      // Verify the original arrays were zero-filled (security check)
      // This confirms memory was overwritten, not just dereferenced
      expect(keyReferences.rootFolderKey.every((b) => b === 0)).toBe(true);
      expect(keyReferences.publicKey.every((b) => b === 0)).toBe(true);
      expect(keyReferences.privateKey.every((b) => b === 0)).toBe(true);
    });

    it('should handle clearing when keys are already null', () => {
      // Should not throw when clearing empty state
      expect(() => {
        useVaultStore.getState().clearVaultKeys();
      }).not.toThrow();

      const state = useVaultStore.getState();
      expect(state.rootFolderKey).toBeNull();
      expect(state.isInitialized).toBe(false);
    });
  });

  describe('useFolderStore.clearFolders', () => {
    it('should zero-fill all folder keys on clearFolders', () => {
      // Setup: Create multiple folders with keys
      const folder1Key = new Uint8Array(32).fill(0x11);
      const folder1IpnsKey = new Uint8Array(32).fill(0x12);
      const folder2Key = new Uint8Array(32).fill(0x21);
      const folder2IpnsKey = new Uint8Array(32).fill(0x22);
      const folder3Key = new Uint8Array(32).fill(0x31);
      const folder3IpnsKey = new Uint8Array(32).fill(0x32);

      // Keep references for verification
      const keyReferences = [
        { folderKey: folder1Key, ipnsPrivateKey: folder1IpnsKey },
        { folderKey: folder2Key, ipnsPrivateKey: folder2IpnsKey },
        { folderKey: folder3Key, ipnsPrivateKey: folder3IpnsKey },
      ];

      // Create folder nodes
      const folders: Record<string, FolderNode> = {
        root: {
          id: 'root',
          name: 'Root',
          ipnsName: 'k51qzi5uqu5root',
          parentId: null,
          children: [],
          isLoaded: true,
          isLoading: false,
          sequenceNumber: 0n,
          folderKey: folder1Key,
          ipnsPrivateKey: folder1IpnsKey,
        },
        'folder-1': {
          id: 'folder-1',
          name: 'Documents',
          ipnsName: 'k51qzi5uqu5docs',
          parentId: 'root',
          children: [],
          isLoaded: true,
          isLoading: false,
          sequenceNumber: 5n,
          folderKey: folder2Key,
          ipnsPrivateKey: folder2IpnsKey,
        },
        'folder-2': {
          id: 'folder-2',
          name: 'Photos',
          ipnsName: 'k51qzi5uqu5photos',
          parentId: 'root',
          children: [],
          isLoaded: false,
          isLoading: false,
          sequenceNumber: 3n,
          folderKey: folder3Key,
          ipnsPrivateKey: folder3IpnsKey,
        },
      };

      // Set folders in store
      useFolderStore.setState({ folders, currentFolderId: 'root' });

      // Verify folders are set
      expect(Object.keys(useFolderStore.getState().folders)).toHaveLength(3);

      // Clear folders
      useFolderStore.getState().clearFolders();

      // Verify state is cleared
      const stateAfter = useFolderStore.getState();
      expect(Object.keys(stateAfter.folders)).toHaveLength(0);
      expect(stateAfter.currentFolderId).toBeNull();
      expect(stateAfter.breadcrumbs).toHaveLength(0);

      // Verify ALL folder keys were zero-filled
      for (const ref of keyReferences) {
        expect(ref.folderKey.every((b) => b === 0)).toBe(true);
        expect(ref.ipnsPrivateKey.every((b) => b === 0)).toBe(true);
      }
    });

    it('should handle clearing when no folders exist', () => {
      expect(() => {
        useFolderStore.getState().clearFolders();
      }).not.toThrow();

      expect(Object.keys(useFolderStore.getState().folders)).toHaveLength(0);
    });
  });

  describe('SECURITY: logout should clear ALL stores', () => {
    it('should clear all cryptographic material when simulating logout flow', () => {
      // Setup: Initialize both stores with keys
      const vaultRootKey = new Uint8Array(32).fill(0xaa);
      const vaultIpnsPublic = new Uint8Array(32).fill(0xbb);
      const vaultIpnsPrivate = new Uint8Array(32).fill(0xcc);
      const folderKey = new Uint8Array(32).fill(0xdd);
      const folderIpnsKey = new Uint8Array(32).fill(0xee);

      // Keep references
      const allKeys = [vaultRootKey, vaultIpnsPublic, vaultIpnsPrivate, folderKey, folderIpnsKey];

      // Initialize vault
      useVaultStore.getState().setVaultKeys({
        rootFolderKey: vaultRootKey,
        rootIpnsKeypair: { publicKey: vaultIpnsPublic, privateKey: vaultIpnsPrivate },
        rootIpnsName: 'k51qzi5uqu5root',
        vaultId: 'test-vault',
      });

      // Initialize folder
      useFolderStore.getState().setFolder({
        id: 'root',
        name: 'Root',
        ipnsName: 'k51qzi5uqu5root',
        parentId: null,
        children: [],
        isLoaded: true,
        isLoading: false,
        sequenceNumber: 0n,
        folderKey,
        ipnsPrivateKey: folderIpnsKey,
      });

      // Verify both stores have data
      expect(useVaultStore.getState().isInitialized).toBe(true);
      expect(Object.keys(useFolderStore.getState().folders)).toHaveLength(1);

      // Simulate logout flow (as done in useAuth.ts)
      // Order matters: clear folder store first, then vault store
      useFolderStore.getState().clearFolders();
      useVaultStore.getState().clearVaultKeys();

      // Verify both stores are cleared
      const vaultState = useVaultStore.getState();
      const folderState = useFolderStore.getState();

      expect(vaultState.rootFolderKey).toBeNull();
      expect(vaultState.rootIpnsKeypair).toBeNull();
      expect(vaultState.isInitialized).toBe(false);
      expect(Object.keys(folderState.folders)).toHaveLength(0);

      // SECURITY: Verify ALL keys were zero-filled
      for (const key of allKeys) {
        expect(key.every((b) => b === 0)).toBe(true);
      }
    });

    it('SECURITY: no keys should be accessible via getState() after logout', () => {
      // Setup keys
      const rootKey = new Uint8Array(32).fill(0xff);
      const publicKey = new Uint8Array(32).fill(0xee);
      const privateKey = new Uint8Array(32).fill(0xdd);

      useVaultStore.getState().setVaultKeys({
        rootFolderKey: rootKey,
        rootIpnsKeypair: { publicKey, privateKey },
        rootIpnsName: 'k51test',
        vaultId: 'vault-1',
      });

      // Clear (logout)
      useFolderStore.getState().clearFolders();
      useVaultStore.getState().clearVaultKeys();

      // Attempt to access keys (simulating XSS attack after logout)
      const vaultState = useVaultStore.getState();
      const folderState = useFolderStore.getState();

      // Keys should be null (not accessible)
      expect(vaultState.rootFolderKey).toBeNull();
      expect(vaultState.rootIpnsKeypair).toBeNull();

      // Even if attacker had reference to original arrays, they're zeroed
      expect(rootKey.every((b) => b === 0)).toBe(true);
      expect(publicKey.every((b) => b === 0)).toBe(true);
      expect(privateKey.every((b) => b === 0)).toBe(true);

      // No folders with keys should exist
      expect(Object.values(folderState.folders)).toHaveLength(0);
    });
  });
});
