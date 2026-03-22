/**
 * IPFS API adapter -- wraps @cipherbox/api-client generated functions
 * with upload progress tracking, cancel support, and download-as-Uint8Array.
 *
 * Progress callbacks are passed via the axios options parameter
 * (onUploadProgress / onDownloadProgress) to the generated functions.
 */
import {
  ipfsControllerUpload,
  ipfsControllerUnpin,
  ipfsControllerGet,
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
      ...(onProgress && {
        onUploadProgress: (event: AxiosProgressEvent) => {
          if (event.total) {
            onProgress(Math.round((event.loaded * 100) / event.total));
          }
        },
      }),
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
 * Supports progress tracking for larger files via axios onDownloadProgress.
 *
 * @param cid - IPFS CID of the file
 * @param onProgress - Optional callback for download progress
 * @returns Encrypted file content as Uint8Array
 */
export async function fetchFromIpfs(
  cid: string,
  onProgress?: DownloadProgressCallback
): Promise<Uint8Array> {
  const blob = await ipfsControllerGet(cid, {
    ...(onProgress && {
      onDownloadProgress: (event: AxiosProgressEvent) => {
        if (event.total) {
          onProgress(event.loaded, event.total);
        }
      },
    }),
  });

  const buffer = await blob.arrayBuffer();
  return new Uint8Array(buffer);
}
