import { isActiveUpload, useDropUpload } from '../../hooks/useDropUpload';
import { useFolderNavigation } from '../../vault/useFolderNavigation';
import { Breadcrumbs } from './Breadcrumbs';
import { EmptyState } from './EmptyState';
import { FileList } from './FileList';
import { UploadListItem } from './UploadListItem';
import { UploadZone } from './UploadZone';

/** The vault browser: where you are, what is in it, and how to move. */
export function FileBrowser() {
  const { rows, breadcrumbs, isLoading, isRoot, error, navigateTo, navigateUp } =
    useFolderNavigation();
  const { uploads, upload, cancel, retry, dismiss } = useDropUpload();
  const settled = !isLoading && error === null;
  // The trail ends at the folder on screen, which is where a drop lands.
  const folder = breadcrumbs.at(-1)?.id ?? null;

  return (
    <div className="file-browser" data-testid="file-browser">
      <Breadcrumbs crumbs={breadcrumbs} onNavigate={navigateTo} />
      {error && (
        <p className="file-browser-error" role="alert" data-testid="file-browser-error">
          {error.message}
        </p>
      )}
      {isLoading && (
        <p className="file-browser-loading" data-testid="file-browser-loading">
          {'// LOADING VAULT...'}
        </p>
      )}
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
      {/* An empty non-root folder still lists, so `[..]` remains reachable. */}
      {settled && (rows.length > 0 || !isRoot) && (
        <FileList
          rows={rows}
          showParentRow={!isRoot}
          onOpen={navigateTo}
          onNavigateUp={navigateUp}
        />
      )}
      {settled && rows.length === 0 && <EmptyState />}
    </div>
  );
}
