import { useCallback, useEffect, useMemo, useState } from 'react';
import { type ConnectionTestResult, type PinningMode } from '@cipherbox/sdk-core';
import {
  wrapKey,
  unwrapKey,
  clearBytes,
  deriveByoConfigIpnsKeypair,
  hexToBytes,
  bytesToHex,
} from '@cipherbox/crypto';
import type { ByoIpfsConfig } from '@cipherbox/core';
import { useAuthStore } from '../../stores/auth.store';
import { useQuotaStore } from '../../stores/quota.store';
import { addToIpfs, fetchFromIpfs } from '../../lib/api/ipfs';
import { createAndPublishIpnsRecord, resolveIpnsRecord } from '../../services/ipns.service';
import { ConnectionTest } from './ConnectionTest';

/** Local storage key for the BYO config IPNS name (not sensitive -- public identifier) */
const BYO_IPNS_NAME_KEY = 'cipherbox-byo-ipns-name';

type SavedConfig = {
  mode: PinningMode;
  endpoint: string;
  authToken: string;
};

/**
 * Encrypt ByoIpfsConfig with user's secp256k1 public key (ECIES).
 * Follows the same pattern as @cipherbox/core registry/bin encrypt.
 */
async function encryptByoConfig(
  config: ByoIpfsConfig,
  userPublicKey: Uint8Array
): Promise<Uint8Array> {
  const plaintext = new TextEncoder().encode(JSON.stringify(config));
  try {
    return await wrapKey(plaintext, userPublicKey);
  } finally {
    clearBytes(plaintext);
  }
}

/**
 * Decrypt ByoIpfsConfig with user's secp256k1 private key (ECIES).
 */
async function decryptByoConfig(
  encrypted: Uint8Array,
  userPrivateKey: Uint8Array
): Promise<ByoIpfsConfig> {
  const plaintext = await unwrapKey(encrypted, userPrivateKey);
  try {
    const json = new TextDecoder().decode(plaintext);
    return JSON.parse(json) as ByoIpfsConfig;
  } finally {
    clearBytes(plaintext);
  }
}

/**
 * STORAGE tab for the Settings page.
 *
 * Allows users to configure their IPFS pinning mode, external node settings,
 * test connections, and persist BYO config as an encrypted IPNS entry
 * (zero-knowledge -- server never sees credentials).
 */
export function StorageTab() {
  const [mode, setMode] = useState<PinningMode>('cipherbox');
  const [endpoint, setEndpoint] = useState('');
  const [authToken, setAuthToken] = useState('');
  const [savedConfig, setSavedConfig] = useState<SavedConfig | null>(null);
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [saveError, setSaveError] = useState<string | null>(null);

  const vaultKeypair = useAuthStore((s) => s.vaultKeypair);
  const teeKeys = useAuthStore((s) => s.teeKeys);
  const { usedBytes } = useQuotaStore();

  // Dirty tracking
  const isDirty = useMemo(() => {
    if (!savedConfig) {
      return mode !== 'cipherbox' || endpoint !== '' || authToken !== '';
    }
    return (
      mode !== savedConfig.mode ||
      endpoint !== savedConfig.endpoint ||
      authToken !== savedConfig.authToken
    );
  }, [mode, endpoint, authToken, savedConfig]);

  const endpointDirty = savedConfig ? endpoint !== savedConfig.endpoint : endpoint !== '';
  const tokenDirty = savedConfig ? authToken !== savedConfig.authToken : authToken !== '';

  // Load saved config from encrypted IPNS entry on mount
  useEffect(() => {
    let cancelled = false;

    async function loadConfig() {
      if (!vaultKeypair?.privateKey) {
        setIsLoading(false);
        return;
      }

      try {
        const keypair = await deriveByoConfigIpnsKeypair(vaultKeypair.privateKey);
        const storedIpnsName = localStorage.getItem(BYO_IPNS_NAME_KEY);

        // Use stored name or derived name
        const ipnsName = storedIpnsName || keypair.ipnsName;

        // Try resolving the BYO config IPNS record
        const resolved = await resolveIpnsRecord(ipnsName);
        if (cancelled) return;

        if (resolved?.cid) {
          const encrypted = await fetchFromIpfs(resolved.cid);
          if (cancelled) return;

          const config = await decryptByoConfig(encrypted, vaultKeypair.privateKey);
          if (cancelled) return;

          setMode(config.pinningMode);
          setEndpoint(config.externalProvider?.endpoint ?? '');
          setAuthToken(config.externalProvider?.authToken ?? '');
          setSavedConfig({
            mode: config.pinningMode,
            endpoint: config.externalProvider?.endpoint ?? '',
            authToken: config.externalProvider?.authToken ?? '',
          });

          // Cache the IPNS name
          localStorage.setItem(BYO_IPNS_NAME_KEY, ipnsName);
        }
      } catch {
        // No saved config or decryption failed -- use defaults
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    }

    loadConfig();
    return () => {
      cancelled = true;
    };
  }, [vaultKeypair]);

  const handleSave = useCallback(async () => {
    if (!vaultKeypair?.privateKey || !vaultKeypair?.publicKey || isSaving) return;
    setIsSaving(true);
    setSaveError(null);

    try {
      // 1. Construct ByoIpfsConfig
      const config: ByoIpfsConfig = {
        pinningMode: mode,
        externalProvider:
          mode !== 'cipherbox'
            ? {
                endpoint,
                authToken,
                protocol: testResult?.protocol ?? 'kubo',
                providerName: testResult?.version,
              }
            : null,
      };

      // 2. Encrypt with user's public key (ECIES)
      const encrypted = await encryptByoConfig(config, vaultKeypair.publicKey);

      // 3. Upload encrypted blob to IPFS (pass typed array directly per CLAUDE.md)
      const blob = new Blob([encrypted as BlobPart]);
      const { cid } = await addToIpfs(blob);

      // 4. Derive dedicated IPNS keypair for BYO config
      const byoKeypair = await deriveByoConfigIpnsKeypair(vaultKeypair.privateKey);

      // 5. Get current sequence number (try resolving existing)
      let sequenceNumber = BigInt(0);
      const storedIpnsName = localStorage.getItem(BYO_IPNS_NAME_KEY);
      if (storedIpnsName) {
        try {
          const existing = await resolveIpnsRecord(storedIpnsName);
          if (existing?.sequenceNumber) {
            sequenceNumber = BigInt(existing.sequenceNumber);
          }
        } catch {
          // First publish -- sequence 0
        }
      }

      // 6. Wrap IPNS private key with TEE public key for republishing
      let encryptedIpnsPrivateKey: string | undefined;
      let keyEpoch: number | undefined;
      if (teeKeys?.currentPublicKey) {
        const teePublicKey = hexToBytes(teeKeys.currentPublicKey);
        const wrappedKey = await wrapKey(byoKeypair.privateKey, teePublicKey);
        encryptedIpnsPrivateKey = bytesToHex(wrappedKey);
        keyEpoch = teeKeys.currentEpoch;
      }

      // 7. Publish encrypted blob via IPNS
      await createAndPublishIpnsRecord({
        ipnsPrivateKey: byoKeypair.privateKey,
        ipnsName: byoKeypair.ipnsName,
        metadataCid: cid,
        sequenceNumber,
        encryptedIpnsPrivateKey,
        keyEpoch,
      });

      // 8. Store IPNS name in localStorage (public identifier, not sensitive)
      localStorage.setItem(BYO_IPNS_NAME_KEY, byoKeypair.ipnsName);

      // 9. Update saved config state
      setSavedConfig({
        mode,
        endpoint,
        authToken,
      });

      // 10. Trigger migration if provider changed and user has existing pins
      const providerChanged =
        savedConfig &&
        (savedConfig.mode !== mode || savedConfig.endpoint !== endpoint) &&
        usedBytes > 0;

      if (providerChanged && teeKeys?.currentPublicKey) {
        // ECIES-wrap source and destination provider configs for TEE
        const teePublicKey = hexToBytes(teeKeys.currentPublicKey);

        const sourceConfig = JSON.stringify(
          savedConfig.mode !== 'cipherbox'
            ? {
                endpoint: savedConfig.endpoint,
                authToken: savedConfig.authToken,
                protocol: 'kubo',
              }
            : { endpoint: 'cipherbox', protocol: 'cipherbox' }
        );
        const destConfig = JSON.stringify({
          endpoint,
          authToken,
          protocol: testResult?.protocol ?? 'kubo',
        });

        const sourceConfigEncrypted = bytesToHex(
          await wrapKey(new TextEncoder().encode(sourceConfig), teePublicKey)
        );
        const destConfigEncrypted = bytesToHex(
          await wrapKey(new TextEncoder().encode(destConfig), teePublicKey)
        );

        // Migration API call -- Plan 06 will provide migrationApi.start()
        // For now, log the intent; the migration module will be wired in Plan 06
        console.info('[BYO] Migration triggered:', {
          sourceConfigEncrypted: sourceConfigEncrypted.slice(0, 20) + '...',
          destConfigEncrypted: destConfigEncrypted.slice(0, 20) + '...',
        });

        // TODO: await migrationApi.start(sourceConfigEncrypted, destConfigEncrypted);
      }

      // 11. Refetch quota to update advisory status
      useQuotaStore.getState().fetchQuota();
    } catch (err) {
      setSaveError(
        err instanceof Error ? err.message : 'failed to save storage settings. try again.'
      );
    } finally {
      setIsSaving(false);
    }
  }, [
    vaultKeypair,
    mode,
    endpoint,
    authToken,
    testResult,
    teeKeys,
    savedConfig,
    usedBytes,
    isSaving,
  ]);

  const handleDiscard = useCallback(() => {
    if (savedConfig) {
      setMode(savedConfig.mode);
      setEndpoint(savedConfig.endpoint);
      setAuthToken(savedConfig.authToken);
    } else {
      setMode('cipherbox');
      setEndpoint('');
      setAuthToken('');
    }
    setTestResult(null);
    setSaveError(null);
  }, [savedConfig]);

  if (isLoading) {
    return (
      <div className="settings-storage">
        <p className="settings-section-description">loading storage settings...</p>
      </div>
    );
  }

  return (
    <div className="settings-storage">
      {/* Pinning Mode Section */}
      <h3 className="settings-section-heading">{'// pinning mode'}</h3>
      <p className="settings-section-description">
        {
          'configure where your encrypted files are stored. all data remains encrypted -- your node only sees ciphertext.'
        }
      </p>

      <fieldset className="storage-mode-selector" role="radiogroup" aria-label="Pinning mode">
        <div className="storage-mode-option">
          <label>
            <input
              type="radio"
              name="pinning-mode"
              value="cipherbox"
              checked={mode === 'cipherbox'}
              onChange={() => setMode('cipherbox')}
              aria-describedby="hint-cipherbox"
            />
            <span className="storage-mode-label">{'cipherbox only'}</span>
          </label>
          <p className="storage-mode-hint" id="hint-cipherbox">
            {'files pinned to cipherbox infrastructure (default)'}
          </p>
        </div>
        <div className="storage-mode-option">
          <label>
            <input
              type="radio"
              name="pinning-mode"
              value="external"
              checked={mode === 'external'}
              onChange={() => setMode('external')}
              aria-describedby="hint-external"
            />
            <span className="storage-mode-label">{'external only'}</span>
          </label>
          <p className="storage-mode-hint" id="hint-external">
            {'files pinned directly to your node. upload fails if node is unreachable.'}
          </p>
        </div>
        <div className="storage-mode-option">
          <label>
            <input
              type="radio"
              name="pinning-mode"
              value="dual"
              checked={mode === 'dual'}
              onChange={() => setMode('dual')}
              aria-describedby="hint-dual"
            />
            <span className="storage-mode-label">{'dual-pin (both)'}</span>
          </label>
          <p className="storage-mode-hint" id="hint-dual">
            {'primary pin to cipherbox, best-effort mirror to your node.'}
          </p>
        </div>
      </fieldset>

      {/* Provider Configuration (shown when external or dual) */}
      {mode !== 'cipherbox' && (
        <div className="storage-provider-config">
          <h3 className="settings-section-heading">{'// external node'}</h3>

          <label className="storage-field">
            <span
              className={`storage-field-label ${endpointDirty ? 'storage-field-modified' : ''}`}
            >
              {endpointDirty ? '*endpoint url' : 'endpoint url'}
            </span>
            <input
              type="url"
              className="storage-input"
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
              placeholder="https://your-node.example.com:5001"
            />
          </label>

          <label className="storage-field">
            <span className={`storage-field-label ${tokenDirty ? 'storage-field-modified' : ''}`}>
              {tokenDirty ? '*auth token' : 'auth token'}
            </span>
            <input
              type="password"
              className="storage-input"
              value={authToken}
              onChange={(e) => setAuthToken(e.target.value)}
              placeholder="bearer token or api key"
            />
          </label>

          <ConnectionTest endpoint={endpoint} authToken={authToken} onTestResult={setTestResult} />
        </div>
      )}

      {/* Save error display */}
      {saveError && (
        <div className="connection-test-error" role="alert" aria-live="polite">
          {'> '}
          {saveError}
        </div>
      )}

      {/* Save/Discard buttons (shown when dirty) */}
      {isDirty && (
        <div className="storage-actions">
          <button
            type="button"
            className="storage-save-btn"
            disabled={mode !== 'cipherbox' && !testResult?.success}
            aria-disabled={mode !== 'cipherbox' && !testResult?.success}
            onClick={handleSave}
          >
            {isSaving ? '[--saving...]' : '[--save]'}
          </button>
          <button type="button" className="storage-discard-btn" onClick={handleDiscard}>
            {'[--discard]'}
          </button>
        </div>
      )}
    </div>
  );
}
