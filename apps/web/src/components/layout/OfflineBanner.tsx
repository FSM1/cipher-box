import { useStaleness } from '../../engine/useStaleness';
import { useOnlineStatus } from '../../hooks/useOnlineStatus';

/**
 * The staleness ladder's bottom rung, at banner scale (blueprint/web-client.md
 * "Staleness ladder rendering"). Either signal alone raises it: the browser
 * notices a dropped link first, and the engine's rung outlives a link that is
 * up but answers nothing.
 */
export function OfflineBanner() {
  const online = useOnlineStatus();
  const staleness = useStaleness();

  if (online && staleness !== 'offline') return null;

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
