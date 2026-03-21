/**
 * IPFS API adapter -- wraps @cipherbox/api-client generated functions
 * with upload progress tracking, cancel support, and download-as-Uint8Array.
 *
 * Upload progress and cancel tokens are passed via the options parameter
 * (AxiosRequestConfig) to the generated function. Download progress uses
 * the fetch ReadableStream API for streaming byte counts, falling back
 * to a simple arrayBuffer() call when no callback is provided.
 */
import {
  ipfsControllerUpload,
  ipfsControllerUnpin,
  ipfsControllerGet,
  getApiClientConfig,
} from '@cipherbox/api-client';
import type { AxiosProgressEvent, CancelToken } from '@cipherbox/api-client';

export type AddResponse = { cid: string; size: number; recorded: boolean };

export type DownloadProgressCallback = (loaded: number, total: number) => void;

/**
 * Upload encrypted file to IPFS via backend relay.
 * Uses axios for upload progress tracking and cancellation.
 */
export async function addToIpfs(
  encryptedFile: Blob,
  onProgress?: (percent: number) => void,
  cancelToken?: CancelToken
): Promise<AddResponse> {
  const result = await ipfsControllerUpload(
    { file: encryptedFile },
    {
      onUploadProgress: (event: AxiosProgressEvent) => {
        if (event.total && onProgress) {
          onProgress(Math.round((event.loaded * 100) / event.total));
        }
      },
      cancelToken,
    }
  );

  return { cid: result.cid, size: result.size, recorded: result.recorded };
}

/**
 * Unpin file from IPFS via backend relay.
 */
export async function unpinFromIpfs(cid: string): Promise<void> {
  await ipfsControllerUnpin({ cid });
}

/**
 * Fetch encrypted file from IPFS via the API proxy.
 * Supports progress tracking for larger files using streaming ReadableStream.
 *
 * @param cid - IPFS CID of the file
 * @param onProgress - Optional callback for download progress
 * @returns Encrypted file content as Uint8Array
 */
export async function fetchFromIpfs(
  cid: string,
  onProgress?: DownloadProgressCallback
): Promise<Uint8Array> {
  // Simple path: no progress tracking -- use the generated function directly
  if (!onProgress) {
    const blob = await ipfsControllerGet(cid);
    const buffer = await blob.arrayBuffer();
    return new Uint8Array(buffer);
  }

  // With progress tracking: use fetch with ReadableStream
  // (axios onDownloadProgress doesn't give reliable byte counts in the browser)
  const config = getApiClientConfig();
  const token = await config.getAccessToken();

  const doFetch = (bearerToken: string) =>
    fetch(`${config.baseUrl}/ipfs/${cid}`, {
      headers: {
        ...(bearerToken ? { Authorization: `Bearer ${bearerToken}` } : {}),
      },
      credentials: config.withCredentials ? 'include' : 'same-origin',
    });

  let response = await doFetch(token);

  // Mirror the shared client's 401 refresh-and-retry behaviour
  if (response.status === 401 && config.refreshAccessToken) {
    const newToken = await config.refreshAccessToken();
    response = await doFetch(newToken);
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch from IPFS: ${response.status}`);
  }

  const contentLength = response.headers.get('Content-Length');
  if (!contentLength) {
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
