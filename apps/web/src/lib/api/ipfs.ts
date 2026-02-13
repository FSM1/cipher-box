import axios, { AxiosProgressEvent, CancelToken } from 'axios';
import { useAuthStore } from '../../stores/auth.store';

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

export type AddResponse = { cid: string; size: number; recorded: boolean };

export type DownloadProgressCallback = (loaded: number, total: number) => void;

/**
 * Upload encrypted file to IPFS via backend relay.
 * Uses axios directly for upload progress tracking (CancelToken not available in apiClient).
 */
export async function addToIpfs(
  encryptedFile: Blob,
  onProgress?: (percent: number) => void,
  cancelToken?: CancelToken
): Promise<AddResponse> {
  const { accessToken } = useAuthStore.getState();

  const formData = new FormData();
  formData.append('file', encryptedFile);

  const response = await axios.post<AddResponse>(`${BASE_URL}/ipfs/upload`, formData, {
    headers: { Authorization: `Bearer ${accessToken}` },
    onUploadProgress: (event: AxiosProgressEvent) => {
      if (event.total && onProgress) {
        const percent = Math.round((event.loaded * 100) / event.total);
        onProgress(percent);
      }
    },
    cancelToken,
  });

  return response.data;
}

/**
 * Unpin file from IPFS via backend relay.
 */
export async function unpinFromIpfs(cid: string): Promise<void> {
  const { accessToken } = useAuthStore.getState();
  await axios.post(
    `${BASE_URL}/ipfs/unpin`,
    { cid },
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
}

/**
 * Fetch encrypted file from IPFS via the API proxy.
 * Supports progress tracking for larger files.
 *
 * @param cid - IPFS CID of the file
 * @param onProgress - Optional callback for download progress
 * @returns Encrypted file content as Uint8Array
 */
export async function fetchFromIpfs(
  cid: string,
  onProgress?: DownloadProgressCallback
): Promise<Uint8Array> {
  const { accessToken } = useAuthStore.getState();
  const response = await fetch(`${BASE_URL}/ipfs/${cid}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch from IPFS: ${response.status}`);
  }

  // If no progress callback or no content-length, just return arrayBuffer
  const contentLength = response.headers.get('Content-Length');
  if (!onProgress || !contentLength) {
    const buffer = await response.arrayBuffer();
    return new Uint8Array(buffer);
  }

  // Stream with progress
  const total = parseInt(contentLength, 10);
  const reader = response.body?.getReader();
  if (!reader) {
    throw new Error('ReadableStream not supported');
  }

  const chunks: Uint8Array[] = [];
  let loaded = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    chunks.push(value);
    loaded += value.length;
    onProgress(loaded, total);
  }

  // Combine chunks
  const result = new Uint8Array(loaded);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }

  return result;
}
