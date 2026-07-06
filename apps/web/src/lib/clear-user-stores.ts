/**
 * Centralized cleanup of all user-scoped Zustand stores.
 *
 * Called from:
 * - useAuth logout (normal logout flow)
 * - apiClient 401 interceptor (forced logout on token refresh failure)
 *
 * Order matters: clear stores holding crypto keys BEFORE clearing auth state,
 * so sensitive key material is zeroed from memory first. [SECURITY: HIGH-02]
 */
import { destroySdkClient } from './sdk-provider';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { useSyncStore } from '../stores/sync.store';
import { useDeviceRegistryStore } from '../stores/device-registry.store';
import { useBinStore } from '../stores/bin.store';
import { useShareStore } from '../stores/share.store';
import { useQuotaStore } from '../stores/quota.store';
import { useMfaStore } from '../stores/mfa.store';
import { useNotificationStore } from '../stores/notification.store';
import { useVaultSettingsStore } from '../stores/vault-settings.store';
import { useAuthStore } from '../stores/auth.store';

export function clearAllUserStores(): void {
  // 0. Destroy SDK client first (clears key caches, event subscriptions)
  destroySdkClient();

  // 1. Clear stores with crypto key material first
  useFolderStore.getState().clearFolders();
  useVaultStore.getState().clearVaultKeys();

  // 2. Clear remaining user-scoped stores
  useSyncStore.getState().reset();
  useDeviceRegistryStore.getState().clearRegistry();
  useBinStore.getState().clearBin();
  useShareStore.getState().clearShares();
  useQuotaStore.getState().reset();
  useMfaStore.getState().reset();
  useNotificationStore.getState().clearNotifications();
  useVaultSettingsStore.getState().clearSettings();

  // 3. Clear auth state last (zeros keypair memory, sets isAuthenticated=false)
  useAuthStore.getState().logout();
}
