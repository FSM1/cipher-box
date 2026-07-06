import { useCallback, useEffect, useRef, useState } from 'react';
import { type VaultSettings, DEFAULT_VAULT_SETTINGS, validateVaultSettings } from '@cipherbox/sdk';
import { useVaultSettingsStore } from '../../stores/vault-settings.store';
import { saveVaultSettings } from '../../services/vault-settings.service';
import { useAuthStore } from '../../stores/auth.store';
import { getSdkClient } from '../../lib/sdk-provider';

/**
 * VAULT tab for the Settings page.
 *
 * Allows users to configure vault parameters: recycle bin retention,
 * delete behavior, file versioning limits, and version cooldown.
 * Settings are saved as encrypted IPNS entries (zero-knowledge).
 */
export function VaultTab() {
  const storeSettings = useVaultSettingsStore((s) => s.settings);
  const isLoaded = useVaultSettingsStore((s) => s.isLoaded);
  const vaultKeypair = useAuthStore((s) => s.vaultKeypair);
  const teeKeys = useAuthStore((s) => s.teeKeys);

  // Local form state
  const [retentionDays, setRetentionDays] = useState(storeSettings.recycleBinRetentionDays);
  const [deleteBehavior, setDeleteBehavior] = useState<VaultSettings['deleteBehavior']>(
    storeSettings.deleteBehavior
  );
  const [maxVersions, setMaxVersions] = useState(storeSettings.maxVersionsPerFile);
  const [cooldownMinutes, setCooldownMinutes] = useState(storeSettings.versionCooldownMinutes);

  const [isSaving, setIsSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const successTimerRef = useRef<ReturnType<typeof setTimeout>>();

  // Cleanup success timer on unmount
  useEffect(() => {
    return () => {
      if (successTimerRef.current) clearTimeout(successTimerRef.current);
    };
  }, []);

  // Sync local form when store updates (e.g., after initial load)
  useEffect(() => {
    if (isLoaded) {
      setRetentionDays(storeSettings.recycleBinRetentionDays);
      setDeleteBehavior(storeSettings.deleteBehavior);
      setMaxVersions(storeSettings.maxVersionsPerFile);
      setCooldownMinutes(storeSettings.versionCooldownMinutes);
    }
  }, [isLoaded, storeSettings]);

  const handleSave = useCallback(async () => {
    if (!vaultKeypair || isSaving) return;
    setIsSaving(true);
    setSaveError(null);
    setSaveSuccess(false);

    try {
      const newSettings = validateVaultSettings({
        version: 'v1',
        recycleBinRetentionDays: retentionDays,
        deleteBehavior,
        maxVersionsPerFile: maxVersions,
        versionCooldownMinutes: cooldownMinutes,
      });

      await saveVaultSettings({
        client: getSdkClient(),
        settings: newSettings,
        userPublicKey: vaultKeypair.publicKey,
        userPrivateKey: vaultKeypair.privateKey,
        teeKeys,
      });

      useVaultSettingsStore.getState().setSettings(newSettings);

      setSaveSuccess(true);
      if (successTimerRef.current) clearTimeout(successTimerRef.current);
      successTimerRef.current = setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save settings');
    } finally {
      setIsSaving(false);
    }
  }, [
    vaultKeypair,
    isSaving,
    retentionDays,
    deleteBehavior,
    maxVersions,
    cooldownMinutes,
    teeKeys,
  ]);

  const handleReset = useCallback(() => {
    setRetentionDays(DEFAULT_VAULT_SETTINGS.recycleBinRetentionDays);
    setDeleteBehavior(DEFAULT_VAULT_SETTINGS.deleteBehavior);
    setMaxVersions(DEFAULT_VAULT_SETTINGS.maxVersionsPerFile);
    setCooldownMinutes(DEFAULT_VAULT_SETTINGS.versionCooldownMinutes);
    setSaveError(null);
    setSaveSuccess(false);
  }, []);

  if (!isLoaded) {
    return (
      <div className="vault-settings">
        <p className="settings-section-description">loading vault settings...</p>
      </div>
    );
  }

  return (
    <div className="vault-settings">
      {/* Recycle Bin Section */}
      <div className="vault-settings-section">
        <h3 className="settings-section-heading">{'// recycle bin'}</h3>

        <label className="vault-settings-label" htmlFor="vault-retention-days">
          retention period (days)
        </label>
        <input
          id="vault-retention-days"
          type="number"
          className="vault-settings-input"
          min={0}
          max={365}
          step={1}
          value={retentionDays}
          onChange={(e) => setRetentionDays(Number(e.target.value))}
        />
        <p className="vault-settings-description">
          items in the recycle bin are auto-purged after this period
        </p>
      </div>

      {/* Delete Behavior Section */}
      <div className="vault-settings-section">
        <h3 className="settings-section-heading">{'// delete behavior'}</h3>

        <fieldset
          className="vault-settings-radio-group"
          role="radiogroup"
          aria-label="Delete behavior"
        >
          <div className="vault-settings-radio-option">
            <label>
              <input
                type="radio"
                name="delete-behavior"
                id="delete-behavior-bin"
                value="bin"
                checked={deleteBehavior === 'bin'}
                onChange={() => setDeleteBehavior('bin')}
              />
              <span className="vault-settings-radio-label">move to recycle bin</span>
            </label>
            <p className="vault-settings-description">
              deleted items can be restored within the retention period
            </p>
          </div>

          <div className="vault-settings-radio-option">
            <label>
              <input
                type="radio"
                name="delete-behavior"
                id="delete-behavior-permanent"
                value="permanent"
                checked={deleteBehavior === 'permanent'}
                onChange={() => setDeleteBehavior('permanent')}
              />
              <span className="vault-settings-radio-label">permanent delete</span>
            </label>
            <p className="vault-settings-description">
              deleted items are immediately and irreversibly removed
            </p>
          </div>
        </fieldset>
      </div>

      {/* File Versioning Section */}
      <div className="vault-settings-section">
        <h3 className="settings-section-heading">{'// file versioning'}</h3>

        <label className="vault-settings-label" htmlFor="vault-max-versions">
          max versions per file
        </label>
        <input
          id="vault-max-versions"
          type="number"
          className="vault-settings-input"
          min={0}
          max={100}
          step={1}
          value={maxVersions}
          onChange={(e) => setMaxVersions(Number(e.target.value))}
        />
        <p className="vault-settings-description">
          older versions are pruned when this limit is exceeded. set to 0 to disable versioning.
        </p>

        <label className="vault-settings-label" htmlFor="vault-cooldown-minutes">
          version cooldown (minutes)
        </label>
        <input
          id="vault-cooldown-minutes"
          type="number"
          className="vault-settings-input"
          min={0}
          max={1440}
          step={1}
          value={cooldownMinutes}
          onChange={(e) => setCooldownMinutes(Number(e.target.value))}
        />
        <p className="vault-settings-description">
          minimum time between automatic version snapshots. set to 0 to create a version on every
          save.
        </p>
      </div>

      {/* Actions */}
      <div className="vault-settings-actions">
        <button
          type="button"
          className="vault-settings-save-btn"
          disabled={isSaving}
          onClick={handleSave}
        >
          {isSaving ? '[SAVING...]' : '[SAVE SETTINGS]'}
        </button>
        <button type="button" className="vault-settings-reset-btn" onClick={handleReset}>
          [RESET TO DEFAULTS]
        </button>
      </div>

      {saveError && (
        <div className="vault-settings-error" role="alert" aria-live="polite">
          {'> '}
          {saveError}
        </div>
      )}

      {saveSuccess && (
        <div className="vault-settings-success" role="status" aria-live="polite">
          {'> settings saved'}
        </div>
      )}
    </div>
  );
}
