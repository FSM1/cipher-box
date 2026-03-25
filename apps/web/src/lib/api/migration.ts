/**
 * Migration API adapter -- thin wrapper over @cipherbox/api-client customInstance.
 *
 * Provides migration lifecycle functions: start, getStatus, pause, resume, cancel.
 * Uses customInstance directly since migration endpoints are not yet in the
 * generated orval client (will be picked up on next `pnpm api:generate`).
 */
import { customInstance } from '@cipherbox/api-client';

export type MigrationStatus = {
  id: string;
  status: 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled';
  totalCids: number;
  migratedCids: number;
  failedCids: number;
  createdAt: string;
  completedAt: string | null;
};

export const migrationApi = {
  /** Start a pin migration with ECIES-encrypted source and destination provider configs. */
  async start(
    sourceConfigEncrypted: string,
    destConfigEncrypted: string
  ): Promise<{ migrationId: string }> {
    return customInstance<{ migrationId: string }>({
      url: '/migration/start',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      data: { sourceConfigEncrypted, destConfigEncrypted },
    });
  },

  /** Get the latest migration status for the current user. Returns null if no migration exists. */
  async getStatus(): Promise<MigrationStatus | null> {
    try {
      return await customInstance<MigrationStatus>({
        url: '/migration/status',
        method: 'GET',
      });
    } catch {
      return null; // No migration exists
    }
  },

  /** Pause an active migration. */
  async pause(migrationId: string): Promise<void> {
    await customInstance<{ message: string }>({
      url: `/migration/${migrationId}/pause`,
      method: 'POST',
    });
  },

  /** Resume a paused migration. */
  async resume(migrationId: string): Promise<void> {
    await customInstance<{ message: string }>({
      url: `/migration/${migrationId}/resume`,
      method: 'POST',
    });
  },

  /** Cancel a migration. */
  async cancel(migrationId: string): Promise<void> {
    await customInstance<{ message: string }>({
      url: `/migration/${migrationId}/cancel`,
      method: 'POST',
    });
  },
};
