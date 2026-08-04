import { useFolderNavigation } from '../../vault/useFolderNavigation';
import { Breadcrumbs } from './Breadcrumbs';
import { EmptyState } from './EmptyState';
import { FileList } from './FileList';

/** The vault browser: where you are, what is in it, and how to move. */
export function FileBrowser() {
  const { rows, breadcrumbs, isLoading, isRoot, hasListing, error, retry, navigateTo, navigateUp } =
    useFolderNavigation();
  // A retryable refusal is a backoff, not a verdict on the folder, so a listing
  // already on screen stays under it.
  const settled = error === null ? !isLoading : retry !== null && hasListing;

  return (
    <div className="file-browser" data-testid="file-browser">
      <Breadcrumbs crumbs={breadcrumbs} onNavigate={navigateTo} />
      {error &&
        (retry === null ? (
          <p className="file-browser-error" role="alert" data-testid="file-browser-error">
            {error.message}
          </p>
        ) : (
          <p className="file-browser-notice" role="status" data-testid="file-browser-notice">
            {error.message}
            <button
              type="button"
              className="terminal-btn"
              onClick={retry}
              data-testid="file-browser-retry"
            >
              retry
            </button>
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
