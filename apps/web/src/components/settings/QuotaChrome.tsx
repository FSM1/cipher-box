import { quotaChrome, reclaimStallReason, toHex } from '@cipherbox/client';
import type { VaultStorageDescriptor } from '@cipherbox/client';
import { formatBytes } from '../../utils/format';

interface QuotaChromeProps {
  /** `null` until the storage read lands. */
  storage: VaultStorageDescriptor | null;
}

/**
 * The stall list is the point of this pane: a debt the pass could not settle
 * can price at nothing, so the pending figure reads drained while the ledger
 * never empties — reporting the figure alone would be the silent failure.
 */
export function QuotaChrome({ storage }: QuotaChromeProps) {
  if (storage === null) return null;
  const chrome = quotaChrome(storage);

  return (
    <div className="settings-quota" data-testid="settings-quota">
      <dl className="settings-facts">
        <dt>used</dt>
        <dd>
          {chrome.usage === null
            ? 'the quota probe did not answer'
            : `${formatBytes(chrome.usage.usedBytes)} of ${formatBytes(chrome.usage.limitBytes)} (${chrome.usage.percent}%)`}
        </dd>
        {chrome.pendingReclaimBytes !== null && (
          <>
            <dt>pending reclaim</dt>
            <dd data-testid="settings-pending-reclaim">
              {formatBytes(chrome.pendingReclaimBytes)}
            </dd>
          </>
        )}
      </dl>

      {chrome.advisory && (
        <p className="settings-quota-advisory" data-testid="settings-quota-advisory">
          {'// advisory: this vault places bytes the hosted store never counts'}
        </p>
      )}

      {chrome.reclaimStalled && (
        <>
          <p className="sharing-note">
            {'// a prune left these unpinned versions owed. the figure above does not'}
            <br />
            {'// price them, so it can read drained while the ledger is not.'}
          </p>
          <ul className="settings-stalls">
            {chrome.stalls.map((stall) => (
              <li
                key={`${toHex(stall.node)}:${stall.target}`}
                className="settings-stall"
                data-testid="settings-reclaim-stall"
              >
                <code>{stall.target}</code>
                <span>{reclaimStallReason(stall.reason)}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
