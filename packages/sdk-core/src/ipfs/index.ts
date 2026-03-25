import axios, { type AxiosProgressEvent, type CancelToken } from 'axios';
import type {
  SdkContext,
  IpfsAddResult,
  ProgressCallback,
  DownloadProgressCallback,
} from '../types';
import { withPerf } from '../perf';

/**
 * Upload encrypted data to IPFS via backend relay.
 * Uses ctx.axiosInstance when available (gets auth interceptors + default headers),
 * falls back to bare axios with manual token injection.
 */
export async function addToIpfs(
  ctx: SdkContext,
  encryptedData: Uint8Array,
  onProgress?: ProgressCallback,
  cancelToken?: CancelToken
): Promise<IpfsAddResult> {
  return withPerf('ipfs:upload', async () => {
    const blob = new Blob([encryptedData as BlobPart]);
    const formData = new FormData();
    formData.append('file', blob);

    const requestConfig = {
      onUploadProgress: (event: AxiosProgressEvent) => {
        if (event.total && onProgress) {
          onProgress(Math.round((event.loaded * 100) / event.total));
        }
      },
      cancelToken,
    };

    if (ctx.axiosInstance) {
      const response = await ctx.axiosInstance.post<IpfsAddResult>(
        '/ipfs/upload',
        formData,
        requestConfig
      );
      return response.data;
    }

    // Fallback: bare axios with manual token (no instance available)
    const token = await ctx.getAccessToken();
    const response = await axios.post<IpfsAddResult>(`${ctx.apiUrl}/ipfs/upload`, formData, {
      headers: { Authorization: `Bearer ${token}` },
      ...requestConfig,
    });
    return response.data;
  });
}

/**
 * Unpin file from IPFS via backend relay.
 */
export async function unpinFromIpfs(ctx: SdkContext, cid: string): Promise<void> {
  return withPerf('ipfs:unpin', async () => {
    if (ctx.axiosInstance) {
      await ctx.axiosInstance.post('/ipfs/unpin', { cid });
      return;
    }

    const token = await ctx.getAccessToken();
    await axios.post(
      `${ctx.apiUrl}/ipfs/unpin`,
      { cid },
      { headers: { Authorization: `Bearer ${token}` } }
    );
  });
}

/**
 * Fetch encrypted data from IPFS via backend relay.
 * Uses native fetch for streaming download progress support.
 * Auth token is obtained from ctx (axiosInstance interceptor isn't used
 * here because fetch provides ReadableStream for progress tracking).
 */
export async function fetchFromIpfs(
  ctx: SdkContext,
  cid: string,
  onProgress?: DownloadProgressCallback
): Promise<Uint8Array> {
  return withPerf('ipfs:download', async () => {
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
  });
}
