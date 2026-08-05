import { useSnapshot } from '../../engine/useSnapshot';
import { useFolderNavigation } from '../../vault/useFolderNavigation';
import { Breadcrumbs } from './Breadcrumbs';
import { DeadLetterNotice } from './DeadLetterNotice';
import { EmptyState } from './EmptyState';
import { FileBrowserActions } from './FileBrowserActions';
import { UploadPanel } from './UploadPanel';

/** The vault browser: where you are, what is in it, and how to move. */
export function FileBrowser() {
  const { rows, folder, breadcrumbs, isLoading, isRoot, error, navigateTo, navigateUp } =
    useFolderNavigation();
  const { view } = useSnapshot();
  const settled = !isLoading && error === null;

  return (
    <div className="file-browser" data-testid="file-browser">
      <Breadcrumbs crumbs={breadcrumbs} onNavigate={navigateTo} />
      <DeadLetterNotice deadLetters={view?.deadLetters ?? []} />
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
      {/* Mounted whatever the route says, so a running upload survives a folder
          change; only its drop target waits for a folder that can take one. */}
      <UploadPanel folder={settled ? folder : null} />
      {settled && (
        <FileBrowserActions
          rows={rows}
          folder={folder}
          showParentRow={!isRoot}
          onOpen={navigateTo}
          onNavigateUp={navigateUp}
        />
      )}
      {settled && rows.length === 0 && <EmptyState />}
    </div>
  );
}
