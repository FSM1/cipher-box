import { isActiveUpload, useDropUpload } from '../../hooks/useDropUpload';
import { UploadListItem } from './UploadListItem';
import { UploadZone } from './UploadZone';

interface UploadPanelProps {
  /** Where a drop lands, or `null` when nothing on screen can take one. */
  folder: Uint8Array | null;
}

/**
 * The upload surface. It owns the upload rows so a block-confirmed event
 * repaints them alone, not the listing underneath, and it outlives a folder
 * change so a running upload keeps its row, its controls, and its subscription
 * to the engine's reports — only the drop target follows the folder.
 */
export function UploadPanel({ folder }: UploadPanelProps) {
  const { uploads, upload, cancel, retry, dismiss } = useDropUpload();

  return (
    <>
      {folder !== null && (
        <UploadZone
          onFiles={(files) => upload(files, folder)}
          busy={uploads.some((entry) => isActiveUpload(entry.phase))}
        />
      )}
      {uploads.length > 0 && (
        <div className="upload-list" role="list" data-testid="upload-list">
          {uploads.map((entry) => (
            <UploadListItem
              key={entry.id}
              upload={entry}
              onCancel={cancel}
              onRetry={retry}
              onDismiss={dismiss}
            />
          ))}
        </div>
      )}
    </>
  );
}
