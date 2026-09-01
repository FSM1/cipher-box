import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import type { SettingsOrigin } from '@cipherbox/client';
import { RestoreIntoDialog } from '../components/bin/RestoreIntoDialog';
import { AppShell } from '../components/layout/AppShell';
import { ConfirmDangerDialog } from '../components/ui/ConfirmDangerDialog';
import { useVaultStorage } from '../providers/VaultStorageProvider';
import { useBin, type BinVerdict } from '../hooks/useBin';
import { binRows, type BinRow } from '../vault/binRows';

/** The refusal another destination can repair; no other one can. */
const TARGET_GONE = 'restoreTargetGone';

/** The vault's bin, behind `RequireAuth`, over the engine's own bin index. */
export function BinPage() {
  const { bin, busy, error, code, reload, clearError, restore, purge } = useBin();
  const { storage } = useVaultStorage();
  const settings = storage?.settings ?? null;
  const retentionDays = settings?.binRetentionDays ?? null;

  const rows = useMemo(
    () => (bin === null ? null : binRows(bin.entries, retentionDays)),
    [bin, retentionDays]
  );

  /** The row whose plain restore the engine refused. */
  const [refused, setRefused] = useState<string | null>(null);
  const [restoring, setRestoring] = useState<BinRow | null>(null);
  const [purging, setPurging] = useState<BinRow | null>(null);
  /** The last command was journaled, so the listed index does not carry it yet. */
  const [queued, setQueued] = useState(false);

  const settle = (verdict: BinVerdict): boolean => {
    setQueued(verdict === 'queued');
    return verdict !== 'refused';
  };

  const restoreHome = async (row: BinRow): Promise<void> => {
    setRefused(settle(await restore(row.id, null)) ? null : row.key);
  };

  const restoreInto = async (into: Uint8Array): Promise<void> => {
    if (restoring === null) return;
    if (settle(await restore(restoring.id, into))) {
      setRestoring(null);
      setRefused(null);
    }
  };

  const purgeEntry = async (): Promise<void> => {
    if (purging === null) return;
    if (settle(await purge(purging.id))) setPurging(null);
  };

  /** A dialog owns the refusal it causes, so it never inherits an older one. */
  const openDialog = (open: (row: BinRow) => void, row: BinRow): void => {
    clearError();
    open(row);
  };

  const readAgain = (): void => {
    setQueued(false);
    void reload();
  };

  const dialogOpen = restoring !== null || purging !== null;

  return (
    <AppShell>
      <div className="route-page" data-testid="bin-page">
        <h2 className="route-heading">bin</h2>
        <p className="sharing-note">
          {'// what this vault deleted, and where a restore puts each one back'}
        </p>

        <Retention days={retentionDays} origin={settings?.origin ?? null} />

        {error !== null && !dialogOpen && (
          <p className="dialog-error" role="alert" data-testid="bin-error">
            {error}
          </p>
        )}

        {bin?.origin === 'stale' && (
          <p className="bin-warning" role="status" data-testid="bin-stale">
            {"// this device's copy of the bin, not the index the vault published"}
          </p>
        )}

        {queued && (
          <p className="bin-warning" role="status" data-testid="bin-queued">
            {
              '// that command is journaled — the vault publishes it as the queue drains, so read again to see the change'
            }
          </p>
        )}

        <BinBody
          rows={rows}
          unestablished={bin?.origin === 'defaults'}
          busy={busy}
          elsewhere={code === TARGET_GONE ? refused : null}
          onRestore={restoreHome}
          onRestoreElsewhere={(row) => openDialog(setRestoring, row)}
          onPurge={(row) => openDialog(setPurging, row)}
        />

        <button
          type="button"
          className="terminal-btn"
          onClick={readAgain}
          disabled={busy}
          data-testid="bin-reload"
        >
          {busy ? 'reading...' : 'read again'}
        </button>
      </div>

      {restoring !== null && (
        <RestoreIntoDialog
          name={restoring.name}
          onClose={() => setRestoring(null)}
          onConfirm={(into) => void restoreInto(into)}
          busy={busy}
          error={error}
        />
      )}
      {purging !== null && (
        <ConfirmDangerDialog
          title={`purge ${purging.name}`}
          message={`destroy "${purging.name}"${
            purging.kind === 'folder' ? ' and everything inside it' : ''
          }? this cannot be undone.`}
          verb="purge"
          busyVerb="purging..."
          testId="purge"
          onClose={() => setPurging(null)}
          onConfirm={() => void purgeEntry()}
          busy={busy}
          error={error}
        />
      )}
    </AppShell>
  );
}

/** The vault's own retention, never a figure this page decided. */
function Retention({ days, origin }: { days: number | null; origin: SettingsOrigin | null }) {
  const line =
    days === null
      ? 'the retention this vault keeps has not been read yet'
      : days === 0
        ? 'this vault deletes outright, so nothing is kept here'
        : origin === 'defaults'
          ? `no settings record loaded, so this vault keeps the documented ${days} days`
          : origin === 'stale'
            ? `this device's copy of your settings keeps a deleted item for ${days} days`
            : `this vault keeps a deleted item for ${days} days`;

  return (
    <p
      className="sharing-note"
      data-testid="bin-retention"
      data-days={days ?? undefined}
      data-origin={origin ?? undefined}
    >
      {`// ${line} — `}
      <Link to="/settings" data-testid="bin-retention-link">
        vault settings
      </Link>
    </p>
  );
}

interface BinBodyProps {
  rows: BinRow[] | null;
  /** No bin index was read, so an empty list is a fallback and not a read. */
  unestablished: boolean;
  busy: boolean;
  /** The row whose restore only another destination can repair. */
  elsewhere: string | null;
  onRestore: (row: BinRow) => void;
  onRestoreElsewhere: (row: BinRow) => void;
  onPurge: (row: BinRow) => void;
}

function BinBody({
  rows,
  unestablished,
  busy,
  elsewhere,
  onRestore,
  onRestoreElsewhere,
  onPurge,
}: BinBodyProps) {
  if (rows === null) {
    return (
      <p className="sharing-note" data-testid="bin-unread">
        {'// the bin has not been read yet'}
      </p>
    );
  }
  if (unestablished) {
    return (
      <p className="sharing-note" data-testid="bin-unestablished">
        {
          '// no bin index loaded — this vault either holds none, or its record did not resolve. nothing deleted is listed here'
        }
      </p>
    );
  }
  if (rows.length === 0) {
    return (
      <p className="sharing-note" data-testid="bin-empty">
        {'// the bin is empty'}
      </p>
    );
  }

  return (
    <ul className="sharing-list" data-testid="bin-list">
      {rows.map((row) => {
        /** Names one row of two that share a name, for a reader who cannot see. */
        const what = `${row.name} from ${row.origin}`;
        return (
          <li
            key={row.key}
            className="sharing-row bin-row"
            data-testid="bin-row"
            data-node={row.key}
          >
            <span className="bin-icon" aria-hidden="true">
              {row.icon}
            </span>
            <span className="bin-name" data-testid="bin-name">
              {row.name}
            </span>
            <span className="details-badge" data-testid="bin-origin">
              {`from ${row.origin}`}
            </span>
            <span className="details-badge" data-testid="bin-deleted">
              {`deleted ${row.deleted}`}
            </span>
            <span className="details-badge" data-testid="bin-expires">
              {row.expires === null ? 'no expiry' : `expires ${row.expires}`}
            </span>
            <button
              type="button"
              className="terminal-btn"
              onClick={() => onRestore(row)}
              disabled={busy}
              data-testid="bin-restore"
              aria-label={`restore ${what}`}
            >
              restore
            </button>
            {elsewhere === row.key && (
              <button
                type="button"
                className="terminal-btn"
                onClick={() => onRestoreElsewhere(row)}
                disabled={busy}
                data-testid="bin-restore-elsewhere"
                aria-label={`restore ${what} into another folder`}
              >
                pick a folder
              </button>
            )}
            <button
              type="button"
              className="terminal-btn"
              onClick={() => onPurge(row)}
              disabled={busy}
              data-testid="bin-purge"
              aria-label={`purge ${what}`}
            >
              purge
            </button>
          </li>
        );
      })}
    </ul>
  );
}
