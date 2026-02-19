/**
 * Hook for lazily resolving file sizes from per-file IPNS metadata.
 *
 * After the v2 migration (per-file IPNS metadata split), file sizes are no
 * longer stored inline in folder metadata (FilePointer). Instead, the size
 * lives in the file's own IPNS record (FileMetadata). This hook resolves
 * file sizes on demand and caches them to avoid redundant network calls.
 */

import { useState, useEffect } from 'react';
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
 * Resolve a file's size from its per-file IPNS metadata record.
 *
 * Returns the cached size if available, otherwise fetches from IPNS.
 * Deduplicates concurrent requests for the same file.
 *
 * @param fileMetaIpnsName - IPNS name of the file's metadata record
 * @param folderKey - Parent folder's decrypted AES-256 key
 * @returns Size in bytes
 */
async function fetchFileSize(fileMetaIpnsName: string, folderKey: Uint8Array): Promise<number> {
  // Return cached value immediately
  const cached = sizeCache.get(fileMetaIpnsName);
  if (cached !== undefined) return cached;

  // Deduplicate in-flight requests
  const pending = pendingRequests.get(fileMetaIpnsName);
  if (pending) return pending;

  // Start new request
  const request = resolveFileMetadata(fileMetaIpnsName, folderKey)
    .then(({ metadata }) => {
      sizeCache.set(fileMetaIpnsName, metadata.size);
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
 * @param fileMetaIpnsName - IPNS name of the file's metadata record (null to skip)
 * @param folderKey - Parent folder's decrypted AES-256 key (null to skip)
 * @returns File size in bytes, or null if not yet resolved
 *
 * @example
 * ```tsx
 * function FileRow({ file, folderKey }) {
 *   const size = useFileSize(file.fileMetaIpnsName, folderKey);
 *   return <span>{size !== null ? formatBytes(size) : '...'}</span>;
 * }
 * ```
 */
export function useFileSize(
  fileMetaIpnsName: string | null,
  folderKey: Uint8Array | null
): number | null {
  // Check cache synchronously to avoid unnecessary loading flash
  const [size, setSize] = useState<number | null>(() => {
    if (!fileMetaIpnsName) return null;
    return sizeCache.get(fileMetaIpnsName) ?? null;
  });

  useEffect(() => {
    if (!fileMetaIpnsName || !folderKey) {
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

    fetchFileSize(fileMetaIpnsName, folderKey)
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
  }, [fileMetaIpnsName, folderKey]);

  return size;
}

/**
 * Clear the file size cache.
 * Call on logout to ensure no stale data persists across sessions.
 */
export function clearFileSizeCache(): void {
  sizeCache.clear();
  pendingRequests.clear();
}
