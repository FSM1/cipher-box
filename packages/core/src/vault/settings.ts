/**
 * @cipherbox/core - Vault Settings
 *
 * Default vault settings and validation for user-configurable parameters.
 * Settings are stored as encrypted IPNS entries (zero-knowledge).
 */

import type { VaultSettings } from './types';

/**
 * Default vault settings matching current hardcoded behavior.
 * Used as fallback when no user settings exist or when loading fails.
 */
export const DEFAULT_VAULT_SETTINGS: VaultSettings = {
  version: 'v1',
  recycleBinRetentionDays: 30,
  deleteBehavior: 'bin',
  maxVersionsPerFile: 10,
  versionCooldownMinutes: 15,
};

/**
 * Validate and sanitize vault settings input.
 *
 * Clamps out-of-range numeric values to valid bounds and returns
 * DEFAULT_VAULT_SETTINGS for corrupt or non-object input.
 *
 * @param input - Raw parsed settings (e.g., from JSON.parse of decrypted blob)
 * @returns Validated VaultSettings with all fields guaranteed valid
 */
export function validateVaultSettings(input: unknown): VaultSettings {
  if (!input || typeof input !== 'object') return { ...DEFAULT_VAULT_SETTINGS };
  const raw = input as Record<string, unknown>;

  const recycleBinRetentionDays = clamp(
    toNumber(raw.recycleBinRetentionDays, DEFAULT_VAULT_SETTINGS.recycleBinRetentionDays),
    0,
    365
  );
  const deleteBehavior =
    raw.deleteBehavior === 'bin' || raw.deleteBehavior === 'permanent'
      ? raw.deleteBehavior
      : DEFAULT_VAULT_SETTINGS.deleteBehavior;
  const maxVersionsPerFile = clamp(
    toNumber(raw.maxVersionsPerFile, DEFAULT_VAULT_SETTINGS.maxVersionsPerFile),
    0,
    100
  );
  const versionCooldownMinutes = clamp(
    toNumber(raw.versionCooldownMinutes, DEFAULT_VAULT_SETTINGS.versionCooldownMinutes),
    0,
    1440
  );

  return {
    version: 'v1',
    recycleBinRetentionDays,
    deleteBehavior,
    maxVersionsPerFile,
    versionCooldownMinutes,
  };
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, Math.floor(value)));
}

function toNumber(value: unknown, fallback: number): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}
