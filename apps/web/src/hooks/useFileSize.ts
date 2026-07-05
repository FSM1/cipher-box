/**
 * Hook for lazily resolving file sizes from per-file IPNS metadata.
 *
 * After the v2 migration (per-file IPNS metadata split), file sizes are no
 * longer stored inline in folder metadata (FilePointer). Instead, the size
 * lives in the file's own IPNS record (FileMetadata). This hook resolves
 * file sizes on demand and caches them to avoid redundant network calls.
 */

import { useState, useEffect } from 'react';
import type { SealedChildRef } from '@cipherbox/core';
import { resolveFileMetadata } from '../services/file-metadata.service';

/**
 * Module-level cache: fileMetaIpnsName -> size in bytes.
 * Persists across component mounts/unmounts within the same session.
 * Cleared on page reload (acceptable since IPNS data is fetched fresh anyway).
 */
const sizeCache = new Map<string, number>();

/**
 * Track in-flight requests to avoid duplicate fetches for the same file.
 * Maps fileMetaIpnsName -> Promise that resolves to size (or rejects).
 */
const pendingRequests = new Map<string, Promise<number>>();

/**
 * Generation counter to prevent in-flight promises from repopulating cache
 * after clearFileSizeCache() is called (e.g., on logout).
 */
let cacheGeneration = 0;

/**
 * Resolve a file's size from its per-file IPNS metadata record.
 *
 * Returns the cached size if available, otherwise fetches from IPNS.
 * Deduplicates concurrent requests for the same file.
 *
 * @param fileRef - The file's SealedChildRef (carries ipnsName + readKeySealed + generation)
 * @param folderKey - Parent folder's decrypted AES-256 key
 * @returns Size in bytes
 */
async function fetchFileSize(fileRef: SealedChildRef, folderKey: Uint8Array): Promise<number> {
  const fileMetaIpnsName = fileRef.ipnsName;

  // Return cached value immediately
  const cached = sizeCache.get(fileMetaIpnsName);
  if (cached !== undefined) return cached;

  // Deduplicate in-flight requests
  const pending = pendingRequests.get(fileMetaIpnsName);
  if (pending) return pending;

  // Capture generation at call time to detect stale writes after cache clear
  const gen = cacheGeneration;

  // Start new request
  const request = resolveFileMetadata(fileRef, folderKey)
    .then(({ metadata }) => {
      if (cacheGeneration === gen) {
        sizeCache.set(fileMetaIpnsName, metadata.size);
      }
      pendingRequests.delete(fileMetaIpnsName);
      return metadata.size;
    })
    .catch((err) => {
      pendingRequests.delete(fileMetaIpnsName);
      throw err;
    });

  pendingRequests.set(fileMetaIpnsName, request);
  return request;
}

/**
 * Hook to lazily resolve a file's size from per-file IPNS metadata.
 *
 * Returns `null` while loading, or the size in bytes once resolved.
 * Silently returns `null` on error (size is non-critical UI data).
 *
 * @param fileRef - The file's SealedChildRef (null to skip)
 * @param folderKey - Parent folder's decrypted AES-256 key (null to skip)
 * @returns File size in bytes, or null if not yet resolved
 *
 * @example
 * ```tsx
 * function FileRow({ file, folderKey }) {
 *   const size = useFileSize(file, folderKey);
 *   return <span>{size !== null ? formatBytes(size) : '...'}</span>;
 * }
 * ```
 */
export function useFileSize(
  fileRef: SealedChildRef | null,
  folderKey: Uint8Array | null
): number | null {
  const fileMetaIpnsName = fileRef?.ipnsName ?? null;

  // Check cache synchronously to avoid unnecessary loading flash
  const [size, setSize] = useState<number | null>(() => {
    if (!fileMetaIpnsName) return null;
    return sizeCache.get(fileMetaIpnsName) ?? null;
  });

  useEffect(() => {
    if (!fileRef || !fileMetaIpnsName || !folderKey) {
      setSize(null);
      return;
    }

    // If already cached, set immediately (handles re-mount with cached data)
    const cached = sizeCache.get(fileMetaIpnsName);
    if (cached !== undefined) {
      setSize(cached);
      return;
    }

    let cancelled = false;

    fetchFileSize(fileRef, folderKey)
      .then((resolvedSize) => {
        if (!cancelled) {
          setSize(resolvedSize);
        }
      })
      .catch(() => {
        // Size is non-critical; silently leave as null
        if (!cancelled) {
          setSize(null);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [fileRef, fileMetaIpnsName, folderKey]);

  return size;
}

/**
 * Clear the file size cache.
 * Call on logout to ensure no stale data persists across sessions.
 */
export function clearFileSizeCache(): void {
  cacheGeneration++;
  sizeCache.clear();
  pendingRequests.clear();
}
