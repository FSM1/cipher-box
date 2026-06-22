/**
 * VersionHistory — error surfacing on missing vault private key (D-14)
 *
 * Exercises the REAL production guard `vaultKeyMissingError` used by
 * VersionHistory.handleDownloadVersion: when the vault private key is missing it
 * returns a user-visible message (the callback surfaces it via setActionError and
 * aborts) instead of silently returning; when present it returns null so the
 * download proceeds. Testing the shared helper means a regression here fails.
 */

import { describe, it, expect } from 'vitest';
import { vaultKeyMissingError } from '../version-download-guard';

describe('vaultKeyMissingError (D-14 error surfacing)', () => {
  it('returns a user-visible message when privateKey is undefined', () => {
    expect(vaultKeyMissingError(undefined)).toBe('Cannot download: vault key not available');
  });

  it('returns a user-visible message when privateKey is null', () => {
    expect(vaultKeyMissingError(null)).toBe('Cannot download: vault key not available');
  });

  it('returns null when privateKey is present so the download proceeds', () => {
    const privateKey = new Uint8Array(32).fill(1);
    expect(vaultKeyMissingError(privateKey)).toBeNull();
  });
});
