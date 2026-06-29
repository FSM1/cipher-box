/**
 * Shared test helpers for CipherBoxClient unit tests.
 *
 * Note: vi.mock() calls cannot be extracted here because Vitest hoists
 * them to the top of each test file. Only helper functions and fixtures
 * are shared.
 */
import { vi } from 'vitest';
import { CipherBoxClient } from '../client';
import type { CipherBoxClientConfig } from '../types';

export function createTestConfig(
  overrides?: Partial<CipherBoxClientConfig>
): CipherBoxClientConfig {
  return {
    apiUrl: 'http://localhost:3000',
    getAccessToken: vi.fn().mockResolvedValue('test-token'),
    vaultKeypair: {
      publicKey: new Uint8Array(33).fill(1),
      privateKey: new Uint8Array(32).fill(2),
    },
    rootIpnsName: 'k51test',
    rootFolderKey: new Uint8Array(32).fill(3),
    ...overrides,
  };
}

export function setupFolder(client: CipherBoxClient, ipnsName = 'folder-ipns', now = Date.now()) {
  // SealedChildRef shape (node/v3) — old FolderChild fields kept as extras for
  // quarantined tests that still reference them. Required fields: ipnsName,
  // generation, versionFloor, readKeySealed (phase 62 compile gate).
  const child = {
    // SealedChildRef required fields
    name: 'test.txt',
    ipnsName: 'k51file',
    generation: 0,
    versionFloor: 0n,
    readKeySealed: 'sealed-key-hex',
    // Legacy FolderChild fields retained for quarantined test reads
    type: 'file' as const,
    id: 'file1',
    fileMetaIpnsName: 'k51file',
    ipnsPrivateKeyEncrypted: 'abc',
    createdAt: now,
    modifiedAt: now,
  };
  client.getFolderTree().set(ipnsName, {
    ipnsName,
    folderKey: new Uint8Array(32).fill(1),
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(2),
      privateKey: new Uint8Array(64).fill(3),
    },
    sequenceNumber: 1n,
    children: [{ ...child }],
    metadata: null,
    lastLoadedAt: now,
  });
  return { ...child };
}
