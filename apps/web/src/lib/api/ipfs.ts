import axios, { AxiosProgressEvent, CancelToken } from 'axios';
import { useAuthStore } from '../../stores/auth.store';

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

export type AddResponse = { cid: string; size: number };

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

  const response = await axios.post<AddResponse>(`${BASE_URL}/ipfs/add`, formData, {
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
