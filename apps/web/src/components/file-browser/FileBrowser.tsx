import { useFolderNavigation } from '../../vault/useFolderNavigation';
import { Breadcrumbs } from './Breadcrumbs';
import { EmptyState } from './EmptyState';
import { FileList } from './FileList';

/** The vault browser: where you are, what is in it, and how to move. */
export function FileBrowser() {
  const {
    rows,
    breadcrumbs,
    isLoading,
    isRoot,
    error,
    isRecoverable,
    navigateTo,
    navigateUp,
    retry,
  } = useFolderNavigation();
  // A recoverable refusal is a backoff, not a verdict on the folder, so the
  // last-known-good listing stays on screen underneath it.
  const settled = !isLoading && (error === null || isRecoverable);

  return (
    <div className="file-browser" data-testid="file-browser">
      <Breadcrumbs crumbs={breadcrumbs} onNavigate={navigateTo} />
      {error &&
        (isRecoverable ? (
          <p className="file-browser-notice" role="status" data-testid="file-browser-notice">
            {error.message}
            <button type="button" onClick={retry} data-testid="file-browser-retry">
              {'RETRY'}
            </button>
          </p>
        ) : (
          <p className="file-browser-error" role="alert" data-testid="file-browser-error">
            {error.message}
          </p>
        ))}
      {isLoading && (
        <p className="file-browser-loading" data-testid="file-browser-loading">
          {'// LOADING VAULT...'}
        </p>
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
