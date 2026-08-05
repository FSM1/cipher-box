import { isActiveUpload, useDropUpload } from '../../hooks/useDropUpload';
import { UploadListItem } from './UploadListItem';
import { UploadZone } from './UploadZone';

interface UploadPanelProps {
  /** Where a drop lands: the folder on screen. */
  folder: Uint8Array;
}

/**
 * The upload surface for one folder. It owns the upload rows so a block-confirmed
 * event repaints them alone, not the listing underneath.
 */
export function UploadPanel({ folder }: UploadPanelProps) {
  const { uploads, upload, cancel, retry, dismiss } = useDropUpload();

  return (
    <>
      <UploadZone
        onFiles={(files) => upload(files, folder)}
        busy={uploads.some((entry) => isActiveUpload(entry.phase))}
      />
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
