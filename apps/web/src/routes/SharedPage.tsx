import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { toHex } from '@cipherbox/client';
import { AppShell } from '../components/layout/AppShell';
import { useReceivedShares } from '../hooks/useReceivedShares';
import { folderPath } from '../lib/nodeId';
import { shareStanding, type ReceivedShareStanding } from '../sharing/receivedShares';

interface Row {
  scope: string;
  /** The vault-browser route for the scope root: a share opens in the one browser. */
  path: string;
  sharer: string;
  displayName: string;
  permission: string;
  /** The engine's own class name, or `none` where no pass has answered. */
  resolution: string;
  standing: ReceivedShareStanding;
}

/**
 * The shares this vault accepted, behind `RequireAuth` (blueprint/web-client.md
 * "Composition"). Each row carries the engine's own resolution verdict, so a
 * removal the owner published is discovered here rather than delivered.
 */
export function SharedPage() {
  const { shares, busy, error, reload } = useReceivedShares();

  const rows: Row[] | null = useMemo(
    () =>
      shares?.map((share) => ({
        scope: toHex(share.scope),
        path: folderPath(share.scope),
        sharer: toHex(share.sharerIdentityPublicKey),
        displayName: share.displayName,
        permission: share.permission,
        resolution: share.resolution ?? 'none',
        standing: shareStanding(share.resolution),
      })) ?? null,
    [shares]
  );

  return (
    <AppShell>
      <div className="route-page" data-testid="shared-page">
        <h2 className="route-heading">shared with you</h2>
        <p className="sharing-note">
          {'// every folder another vault granted you, and where each one stands now'}
        </p>

        {error !== null && (
          <p className="dialog-error" role="alert" data-testid="shared-error">
            {error}
          </p>
        )}

        {rows === null ? (
          error === null && (
            <p className="sharing-note" data-testid="shared-unread">
              {'// the accepted list has not been read yet'}
            </p>
          )
        ) : rows.length === 0 ? (
          <p className="sharing-note" data-testid="shared-empty">
            {'// nothing has been shared with you yet'}
          </p>
        ) : (
          <ul className="sharing-list" data-testid="shared-list">
            {rows.map((row) => (
              <li
                key={`${row.sharer}:${row.scope}`}
                className="sharing-row sharing-row--shared"
                data-testid="shared-row"
                data-scope={row.scope}
              >
                <span className="shared-name" data-testid="shared-name">
                  {row.displayName}
                </span>
                <span className="sharing-key" data-testid="shared-sharer">
                  {row.sharer}
                </span>
                <span className="details-badge" data-testid="shared-permission">
                  {row.permission}
                </span>
                <Link
                  className="terminal-btn shared-open"
                  to={row.path}
                  data-testid="shared-open"
                  aria-label={`open ${row.displayName}`}
                >
                  open
                </Link>
                <span
                  className="shared-standing"
                  data-testid="shared-standing"
                  data-resolution={row.resolution}
                  data-tone={row.standing.tone}
                >
                  {row.standing.label}
                </span>
              </li>
            ))}
          </ul>
        )}

        <button
          type="button"
          className="terminal-btn"
          onClick={() => void reload()}
          disabled={busy}
          data-testid="shared-reload"
        >
          {busy ? 'reading...' : 'read again'}
        </button>
      </div>
    </AppShell>
  );
}
