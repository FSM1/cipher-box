/**
 * @cipherbox/core - Vault Settings Tests
 *
 * Unit tests for VaultSettings type validation, default values, and range clamping.
 */

import { describe, it, expect } from 'vitest';
import { DEFAULT_VAULT_SETTINGS, validateVaultSettings } from '../vault/settings';
import type { VaultSettings } from '../vault/types';

describe('VaultSettings', () => {
  describe('DEFAULT_VAULT_SETTINGS', () => {
    it('should have version v1', () => {
      expect(DEFAULT_VAULT_SETTINGS.version).toBe('v1');
    });

    it('should have recycleBinRetentionDays 30', () => {
      expect(DEFAULT_VAULT_SETTINGS.recycleBinRetentionDays).toBe(30);
    });

    it('should have deleteBehavior bin', () => {
      expect(DEFAULT_VAULT_SETTINGS.deleteBehavior).toBe('bin');
    });

    it('should have maxVersionsPerFile 10', () => {
      expect(DEFAULT_VAULT_SETTINGS.maxVersionsPerFile).toBe(10);
    });

    it('should have versionCooldownMinutes 15', () => {
      expect(DEFAULT_VAULT_SETTINGS.versionCooldownMinutes).toBe(15);
    });
  });

  describe('validateVaultSettings', () => {
    it('should return DEFAULT_VAULT_SETTINGS for empty object', () => {
      const result = validateVaultSettings({});
      expect(result).toEqual(DEFAULT_VAULT_SETTINGS);
    });

    it('should return valid full input unchanged', () => {
      const input: VaultSettings = {
        version: 'v1',
        recycleBinRetentionDays: 60,
        deleteBehavior: 'permanent',
        maxVersionsPerFile: 5,
        versionCooldownMinutes: 30,
      };
      const result = validateVaultSettings(input);
      expect(result).toEqual(input);
    });

    it('should clamp recycleBinRetentionDays below 1 to 1', () => {
      const result = validateVaultSettings({ recycleBinRetentionDays: 0 });
      expect(result.recycleBinRetentionDays).toBe(1);
    });

    it('should clamp recycleBinRetentionDays above 365 to 365', () => {
      const result = validateVaultSettings({ recycleBinRetentionDays: 999 });
      expect(result.recycleBinRetentionDays).toBe(365);
    });

    it('should clamp maxVersionsPerFile below 0 to 0', () => {
      const result = validateVaultSettings({ maxVersionsPerFile: -5 });
      expect(result.maxVersionsPerFile).toBe(0);
    });

    it('should clamp maxVersionsPerFile above 100 to 100', () => {
      const result = validateVaultSettings({ maxVersionsPerFile: 200 });
      expect(result.maxVersionsPerFile).toBe(100);
    });

    it('should clamp versionCooldownMinutes below 0 to 0', () => {
      const result = validateVaultSettings({ versionCooldownMinutes: -10 });
      expect(result.versionCooldownMinutes).toBe(0);
    });

    it('should clamp versionCooldownMinutes above 1440 to 1440', () => {
      const result = validateVaultSettings({ versionCooldownMinutes: 5000 });
      expect(result.versionCooldownMinutes).toBe(1440);
    });

    it('should default invalid deleteBehavior to bin', () => {
      const result = validateVaultSettings({ deleteBehavior: 'invalid' });
      expect(result.deleteBehavior).toBe('bin');
    });

    it('should return DEFAULT_VAULT_SETTINGS for null input', () => {
      const result = validateVaultSettings(null);
      expect(result).toEqual(DEFAULT_VAULT_SETTINGS);
    });

    it('should return DEFAULT_VAULT_SETTINGS for undefined input', () => {
      const result = validateVaultSettings(undefined);
      expect(result).toEqual(DEFAULT_VAULT_SETTINGS);
    });

    it('should return DEFAULT_VAULT_SETTINGS for string input', () => {
      const result = validateVaultSettings('not an object');
      expect(result).toEqual(DEFAULT_VAULT_SETTINGS);
    });

    it('should return DEFAULT_VAULT_SETTINGS for number input', () => {
      const result = validateVaultSettings(42);
      expect(result).toEqual(DEFAULT_VAULT_SETTINGS);
    });

    it('should floor fractional recycleBinRetentionDays', () => {
      const result = validateVaultSettings({ recycleBinRetentionDays: 30.7 });
      expect(result.recycleBinRetentionDays).toBe(30);
    });

    it('should floor fractional maxVersionsPerFile', () => {
      const result = validateVaultSettings({ maxVersionsPerFile: 5.9 });
      expect(result.maxVersionsPerFile).toBe(5);
    });

    it('should floor fractional versionCooldownMinutes', () => {
      const result = validateVaultSettings({ versionCooldownMinutes: 15.5 });
      expect(result.versionCooldownMinutes).toBe(15);
    });

    it('should handle NaN numeric fields with defaults', () => {
      const result = validateVaultSettings({
        recycleBinRetentionDays: NaN,
        maxVersionsPerFile: NaN,
        versionCooldownMinutes: NaN,
      });
      expect(result.recycleBinRetentionDays).toBe(30);
      expect(result.maxVersionsPerFile).toBe(10);
      expect(result.versionCooldownMinutes).toBe(15);
    });

    it('should always set version to v1 regardless of input', () => {
      const result = validateVaultSettings({ version: 'v99' });
      expect(result.version).toBe('v1');
    });

    it('should accept deleteBehavior permanent', () => {
      const result = validateVaultSettings({ deleteBehavior: 'permanent' });
      expect(result.deleteBehavior).toBe('permanent');
    });
  });
});
