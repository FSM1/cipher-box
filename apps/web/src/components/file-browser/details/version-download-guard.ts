/**
 * D-14: gate a version download on the presence of the vault private key.
 *
 * Returns a user-visible error message when the key is missing (the caller must
 * surface it and abort), or `null` when the download may proceed. Centralizing
 * this here lets both VersionHistory and its tests exercise the same contract
 * instead of a duplicated inline guard.
 */
export function vaultKeyMissingError(privateKey: Uint8Array | undefined | null): string | null {
  if (!privateKey) {
    return 'Cannot download: vault key not available';
  }
  return null;
}
