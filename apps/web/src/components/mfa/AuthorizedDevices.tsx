import { useCallback, useMemo, useState } from 'react';
import { useMfa } from '../../hooks/useMfa';
import { useDeviceRegistryStore } from '../../stores/device-registry.store';
import { FactorKeyTypeShareDescription } from '@web3auth/mpc-core-kit';

type DeviceFactorDisplay = {
  factorPubHex: string;
  name: string;
  lastActive: string;
  isCurrent: boolean;
};

/**
 * Authorized Devices list for the Security tab.
 *
 * Shows device share factors matched against the device registry for
 * friendly names and last-active timestamps. Excludes seedPhrase and
 * hashedShare factors (shown elsewhere or hidden).
 */
export function AuthorizedDevices() {
  const { getFactors, deleteFactor, factorCount } = useMfa();
  const registry = useDeviceRegistryStore((s) => s.registry);
  const currentDeviceId = useDeviceRegistryStore((s) => s.currentDeviceId);

  const [isRevoking, setIsRevoking] = useState<string | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const [revokeError, setRevokeError] = useState<string | null>(null);

  const factors = useMemo(() => getFactors(), [getFactors]);

  // Build device display list from factors
  const deviceFactors = useMemo((): DeviceFactorDisplay[] => {
    // Filter to device share factors only
    const deviceShareFactors = factors.filter(
      (f) =>
        f.type === FactorKeyTypeShareDescription.DeviceShare ||
        f.type === 'deviceShare' ||
        f.type === 'webDeviceShare'
    );

    // Build a map from deviceId to registry entry for quick lookup
    const registryMap = new Map<string, { name: string; lastSeenAt: number }>();
    if (registry?.devices) {
      for (const device of registry.devices) {
        if (device.status === 'authorized') {
          registryMap.set(device.deviceId, {
            name: device.name,
            lastSeenAt: device.lastSeenAt,
          });
        }
      }
    }

    return deviceShareFactors.map((factor) => {
      const deviceId = factor.additionalMetadata?.deviceId;
      const registryEntry = deviceId ? registryMap.get(deviceId) : undefined;
      const isCurrent = deviceId != null && deviceId === currentDeviceId;

      return {
        factorPubHex: factor.factorPubHex,
        name: registryEntry?.name || factor.additionalMetadata?.browserName || 'Unknown device',
        lastActive: registryEntry?.lastSeenAt
          ? formatRelativeTime(registryEntry.lastSeenAt)
          : 'unknown',
        isCurrent,
      };
    });
  }, [factors, registry, currentDeviceId]);

  const handleRevoke = useCallback(
    async (factorPubHex: string) => {
      setIsRevoking(factorPubHex);
      setRevokeError(null);
      try {
        await deleteFactor(factorPubHex);
        setConfirmRevoke(null);
      } catch (err) {
        setRevokeError(err instanceof Error ? err.message : 'Failed to revoke device');
      } finally {
        setIsRevoking(null);
      }
    },
    [deleteFactor]
  );

  // Need at least 2 factors total (current device + recovery is the minimum)
  const canRevoke = factorCount > 2;

  if (factors.length === 0) {
    return <div className="authorized-devices-loading">loading device factors...</div>;
  }

  if (deviceFactors.length === 0) {
    return <div className="authorized-devices-empty">no device factors found.</div>;
  }

  return (
    <div className="authorized-devices">
      {revokeError && (
        <div className="linked-methods-error" role="alert">
          {revokeError}
          <button
            type="button"
            onClick={() => setRevokeError(null)}
            className="linked-methods-error-dismiss"
            aria-label="Dismiss error"
          >
            [x]
          </button>
        </div>
      )}

      <div className="authorized-devices-list" role="list" aria-label="Authorized devices">
        {deviceFactors.map((device) => (
          <div key={device.factorPubHex} className="authorized-devices-item" role="listitem">
            <div className="authorized-devices-info">
              <span className="authorized-devices-name">{device.name}</span>
              <span className="authorized-devices-meta">{'last active: ' + device.lastActive}</span>
            </div>
            <div className="authorized-devices-actions">
              <span
                className={`authorized-devices-tag ${device.isCurrent ? 'current' : 'authorized'}`}
              >
                {device.isCurrent ? '[CURRENT]' : '[AUTHORIZED]'}
              </span>
              {!device.isCurrent && (
                <>
                  {confirmRevoke === device.factorPubHex ? (
                    <div className="authorized-devices-confirm-inline">
                      <button
                        type="button"
                        className="authorized-devices-revoke-btn"
                        onClick={() => handleRevoke(device.factorPubHex)}
                        disabled={!!isRevoking || !canRevoke}
                        style={{ color: '#EF4444' }}
                      >
                        {isRevoking === device.factorPubHex ? 'revoking...' : '--confirm'}
                      </button>
                      <button
                        type="button"
                        className="authorized-devices-revoke-btn"
                        onClick={() => setConfirmRevoke(null)}
                      >
                        --cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      type="button"
                      className="authorized-devices-revoke-btn"
                      onClick={() => setConfirmRevoke(device.factorPubHex)}
                      disabled={!canRevoke}
                      title={
                        !canRevoke
                          ? 'Cannot revoke: minimum 2 factors required'
                          : 'Revoke this device'
                      }
                      aria-label={`Revoke ${device.name}`}
                    >
                      --revoke
                    </button>
                  )}
                </>
              )}
            </div>
          </div>
        ))}
      </div>

      {!canRevoke && deviceFactors.length > 1 && (
        <div className="authorized-devices-warning" role="alert">
          {'// '}cannot revoke devices: minimum 2 factors required (current device + recovery
          phrase)
        </div>
      )}
    </div>
  );
}

/**
 * Format a Unix ms timestamp as a relative time string.
 */
function formatRelativeTime(timestampMs: number): string {
  const now = Date.now();
  const diff = now - timestampMs;

  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  if (diff < 604_800_000) return `${Math.floor(diff / 86_400_000)}d ago`;

  return new Date(timestampMs).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}
