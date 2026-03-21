import axios, { type AxiosProgressEvent, type CancelToken } from 'axios';
import type {
  SdkContext,
  IpfsAddResult,
  ProgressCallback,
  DownloadProgressCallback,
} from '../types';

/**
 * Upload encrypted data to IPFS via backend relay.
 * Uses axios for upload progress tracking.
 *
 * Replaces: apps/web/src/lib/api/ipfs.ts addToIpfs()
 * Change: Takes SdkContext instead of reading useAuthStore.getState()
 */
export async function addToIpfs(
  ctx: SdkContext,
  encryptedData: Uint8Array,
  onProgress?: ProgressCallback,
  cancelToken?: CancelToken
): Promise<IpfsAddResult> {
  const token = await ctx.getAccessToken();
  const blob = new Blob([encryptedData as BlobPart]);
  const formData = new FormData();
  formData.append('file', blob);

  const response = await axios.post<IpfsAddResult>(`${ctx.apiUrl}/ipfs/upload`, formData, {
    headers: { Authorization: `Bearer ${token}` },
    onUploadProgress: (event: AxiosProgressEvent) => {
      if (event.total && onProgress) {
        onProgress(Math.round((event.loaded * 100) / event.total));
      }
    },
    cancelToken,
  });
  return response.data;
}

/**
 * Unpin file from IPFS via backend relay.
 *
 * Replaces: apps/web/src/lib/api/ipfs.ts unpinFromIpfs()
 * Change: Takes SdkContext instead of reading useAuthStore.getState()
 */
export async function unpinFromIpfs(ctx: SdkContext, cid: string): Promise<void> {
  const token = await ctx.getAccessToken();
  await axios.post(
    `${ctx.apiUrl}/ipfs/unpin`,
    { cid },
    { headers: { Authorization: `Bearer ${token}` } }
  );
}

/**
 * Fetch encrypted data from IPFS via backend relay.
 * Supports download progress tracking.
 *
 * Replaces: apps/web/src/lib/api/ipfs.ts fetchFromIpfs()
 * Change: Takes SdkContext instead of reading useAuthStore.getState()
 */
export async function fetchFromIpfs(
  ctx: SdkContext,
  cid: string,
  onProgress?: DownloadProgressCallback
): Promise<Uint8Array> {
  const token = await ctx.getAccessToken();
  const response = await fetch(`${ctx.apiUrl}/ipfs/${cid}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) throw new Error(`Failed to fetch from IPFS: ${response.status}`);

  const contentLength = response.headers.get('Content-Length');
  if (!onProgress || !contentLength) {
    return new Uint8Array(await response.arrayBuffer());
  }

  const total = parseInt(contentLength, 10);
  const reader = response.body?.getReader();
  if (!reader) throw new Error('ReadableStream not supported');

  const chunks: Uint8Array[] = [];
  let loaded = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    loaded += value.length;
    onProgress(loaded, total);
  }

  const result = new Uint8Array(loaded);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}
