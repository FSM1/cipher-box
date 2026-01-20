import { apiClient } from './client';

export type QuotaResponse = {
  usedBytes: number;
  limitBytes: number;
  remainingBytes: number;
};

export type VaultResponse = {
  ownerPublicKey: string;
  encryptedRootFolderKey: string;
  encryptedRootIpnsPrivateKey: string;
  rootIpnsName: string;
};

export type InitVaultDto = {
  ownerPublicKey: string;
  encryptedRootFolderKey: string;
  encryptedRootIpnsPrivateKey: string;
  rootIpnsName: string;
};

export const vaultApi = {
  /**
   * Get storage quota for the current user.
   */
  getQuota: async (): Promise<QuotaResponse> => {
    const response = await apiClient.get<QuotaResponse>('/vault/quota');
    return response.data;
  },

  /**
   * Get vault data for the current user.
   */
  getVault: async (): Promise<VaultResponse> => {
    const response = await apiClient.get<VaultResponse>('/vault');
    return response.data;
  },

  /**
   * Initialize vault with encrypted keys.
   */
  initVault: async (dto: InitVaultDto): Promise<VaultResponse> => {
    const response = await apiClient.post<VaultResponse>('/vault/init', dto);
    return response.data;
  },
};
