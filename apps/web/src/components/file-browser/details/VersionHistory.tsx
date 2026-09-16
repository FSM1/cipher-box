import { toHex, type VersionEntryDescriptor } from '@cipherbox/client';
import { clampId, formatBytes, formatEpochMillis } from '../../../utils/format';
import { DetailSection, UNKNOWN } from './DetailsPrimitives';

/** How much of a content root CID names a version on screen, from both ends. */
const HEAD = 8;
const TAIL = 6;

interface VersionHistoryProps {
  /** The engine's prior versions, newest first; `null` before the read lands. */
  entries: readonly VersionEntryDescriptor[] | null;
  /** A command is in flight, so no entry may dispatch a second one. */
  busy: boolean;
  /** The last version command's failure. */
  error: string | null;
  onDownload: (entry: VersionEntryDescriptor) => void;
  onRestore: (entry: VersionEntryDescriptor) => void;
  onDelete: (entry: VersionEntryDescriptor) => void;
}

/**
 * One file's prior versions, as the engine reports them. A version is named by
 * its content root CID, which is also what every version command takes.
 */
export function VersionHistory({
  entries,
  busy,
  error,
  onDownload,
  onRestore,
  onDelete,
}: VersionHistoryProps) {
  const listed = entries !== null && entries.length > 0;
  // A failed read leaves no entries, so a section gated on entries alone would
  // report the failure nowhere.
  if (!listed && error === null) return null;

  return (
    <div className="details-version-section" data-testid="version-history">
      <DetailSection label="prior versions" />
      {error !== null && (
        <p className="details-version-error" role="alert" data-testid="version-error">
          {error}
        </p>
      )}
      <ul className="details-version-list">
        {(entries ?? []).map((entry) => {
          const cid = toHex(entry.contentCid);
          const named = shortCid(cid);
          return (
            <li key={cid} className="details-version-entry" data-testid={`version-${cid}`}>
              <span className="details-version-info">
                <span className="details-version-cid">{named}</span>
                <span className="details-version-date">
                  {formatEpochMillis(entry.modifiedAt, UNKNOWN)}
                </span>
                <span className="details-version-size">{formatBytes(Number(entry.size))}</span>
              </span>
              <span className="details-version-actions">
                <button
                  type="button"
                  className="details-version-button"
                  disabled={busy}
                  onClick={() => onDownload(entry)}
                  aria-label={`download version ${named}`}
                >
                  dl
                </button>
                <button
                  type="button"
                  className="details-version-button"
                  disabled={busy}
                  onClick={() => onRestore(entry)}
                  aria-label={`restore version ${named}`}
                >
                  restore
                </button>
                <button
                  type="button"
                  className="details-version-button details-version-button--danger"
                  disabled={busy}
                  onClick={() => onDelete(entry)}
                  aria-label={`delete version ${named}`}
                >
                  rm
                </button>
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** Taken from both ends, so two CIDs sharing a leading run still read apart. */
export function shortCid(cid: string): string {
  return clampId(cid, HEAD, TAIL);
}
