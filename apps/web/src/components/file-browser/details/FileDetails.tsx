import type { VersionEntryDescriptor } from '@cipherbox/client';
import type { FileVersions } from '../../../hooks/useFileVersions';
import type { ListingRow } from '../../../vault/listing';
import {
  DetailRow,
  DetailSection,
  DimValue,
  NodeRows,
  StateRows,
  UNKNOWN,
} from './DetailsPrimitives';
import { VersionHistory } from './VersionHistory';

interface FileDetailsProps {
  row: ListingRow;
  /** This file's prior versions, read beside the snapshot the row carries. */
  versions: FileVersions;
  /** False in a scope this vault only holds a read grant over. */
  writable: boolean;
  /** A write confirms before it dispatches, which the dialog owns. */
  onRestore: (entry: VersionEntryDescriptor) => void;
  onDelete: (entry: VersionEntryDescriptor) => void;
}

/** One file's current version, as the engine snapshot reports it, and its past ones. */
export function FileDetails({ row, versions, writable, onRestore, onDelete }: FileDetailsProps) {
  return (
    <>
      <dl className="details-list" data-testid="file-details">
        <NodeRows row={row} />

        <DetailSection label="content" />
        <DetailRow label="size">
          {row.bytes === null ? <DimValue>{UNKNOWN}</DimValue> : row.size}
        </DetailRow>
        <DetailRow label="bytes">
          {row.bytes === null ? <DimValue>{UNKNOWN}</DimValue> : row.bytes.toString()}
        </DetailRow>
        <DetailRow label="version">
          {row.contentVersion === null ? (
            <DimValue>{UNKNOWN}</DimValue>
          ) : (
            row.contentVersion.toString()
          )}
        </DetailRow>

        <StateRows row={row} />
      </dl>

      <VersionHistory
        entries={versions.entries}
        busy={versions.busy !== null}
        writable={writable}
        error={versions.error}
        onDownload={(entry) => void versions.download(entry.contentCid)}
        onRestore={onRestore}
        onDelete={onDelete}
      />
    </>
  );
}
