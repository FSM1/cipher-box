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
  const child = {
    type: 'file' as const,
    id: 'file1',
    name: 'test.txt',
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
