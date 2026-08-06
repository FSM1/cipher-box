import { useStaleness } from '../../engine/useStaleness';

/**
 * The staleness ladder's bottom rung, at banner scale (blueprint/web-client.md
 * "Staleness ladder rendering").
 */
export function OfflineBanner() {
  if (useStaleness() !== 'offline') return null;

  return (
    <div className="offline-banner" role="status" data-testid="offline-banner">
      <span className="offline-banner-icon" aria-hidden="true">
        [//]
      </span>
      <span className="offline-banner-detail">
        {'// OFFLINE - changes queue on this device and publish when the network returns'}
      </span>
    </div>
  );
}
