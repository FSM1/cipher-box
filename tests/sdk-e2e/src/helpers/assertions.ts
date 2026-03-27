/**
 * Domain-specific assertion helpers for SDK E2E tests.
 */

import { expect } from 'vitest';
import type { CipherBoxClient } from '@cipherbox/sdk';
import type { FolderChild } from '@cipherbox/core';

/**
 * Assert that a folder's in-memory children contain an item with the given name.
 */
export function expectChildNamed(
  client: CipherBoxClient,
  folderIpnsName: string,
  name: string
): void {
  const folder = client.getFolderTree().get(folderIpnsName);
  expect(folder, `Folder ${folderIpnsName} not found in tree`).toBeTruthy();
  const match = folder!.children.find((c) => c.name === name);
  expect(match, `Expected child named "${name}" in folder`).toBeTruthy();
}

/**
 * Assert that a folder does NOT contain an item with the given name.
 */
export function expectNoChildNamed(
  client: CipherBoxClient,
  folderIpnsName: string,
  name: string
): void {
  const folder = client.getFolderTree().get(folderIpnsName);
  expect(folder, `Folder ${folderIpnsName} not found in tree`).toBeTruthy();
  const match = folder!.children.find((c) => c.name === name);
  expect(match, `Expected no child named "${name}" in folder`).toBeUndefined();
}

/**
 * Assert that a folder has exactly N children.
 */
export function expectChildCount(
  client: CipherBoxClient,
  folderIpnsName: string,
  count: number
): void {
  const folder = client.getFolderTree().get(folderIpnsName);
  expect(folder, `Folder ${folderIpnsName} not found in tree`).toBeTruthy();
  expect(folder!.children.length).toBe(count);
}

/**
 * Get a child entry from the folder tree by name.
 * Throws if not found.
 */
export function getChild(
  client: CipherBoxClient,
  folderIpnsName: string,
  name: string
): FolderChild {
  const folder = client.getFolderTree().get(folderIpnsName);
  if (!folder) throw new Error(`Folder ${folderIpnsName} not in tree`);
  const match = folder.children.find((c) => c.name === name);
  if (!match) throw new Error(`Child "${name}" not found in folder`);
  return match;
}

/**
 * Get all children from the folder tree.
 */
export function getChildren(client: CipherBoxClient, folderIpnsName: string): FolderChild[] {
  const folder = client.getFolderTree().get(folderIpnsName);
  if (!folder) throw new Error(`Folder ${folderIpnsName} not in tree`);
  return folder.children;
}

/**
 * Assert byte-for-byte equality between two Uint8Arrays.
 */
export function expectBytesEqual(actual: Uint8Array, expected: Uint8Array): void {
  expect(actual.length).toBe(expected.length);
  expect(Buffer.from(actual).equals(Buffer.from(expected))).toBe(true);
}
