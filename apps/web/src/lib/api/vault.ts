/**
 * Vault API adapter -- thin wrapper over @cipherbox/api-client generated functions.
 *
 * Keeps the `vaultApi.foo()` call style used by useAuth.ts while delegating
 * all HTTP transport to the shared api-client package.
 */
import {
  vaultControllerGetQuota,
  vaultControllerGetVault,
  vaultControllerInitializeVault,
} from '@cipherbox/api-client';
import type { QuotaResponseDto, VaultResponseDto, InitVaultDto } from '@cipherbox/api-client';

export const vaultApi = {
  /** Get storage quota for the current user. */
  getQuota: (): Promise<QuotaResponseDto> => vaultControllerGetQuota(),

  /** Get vault data for the current user. */
  getVault: (): Promise<VaultResponseDto> => vaultControllerGetVault(),

  /** Initialize vault with encrypted keys. */
  initVault: (dto: InitVaultDto): Promise<VaultResponseDto> => vaultControllerInitializeVault(dto),
};
