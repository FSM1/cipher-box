import { isRecoverable } from '../../engine/snapshotStore';
import { useSnapshot } from '../../engine/useSnapshot';
import { useSnapshotStore } from '../../providers/EngineProvider';
import { useFolderNavigation } from '../../vault/useFolderNavigation';
import { Breadcrumbs } from './Breadcrumbs';
import { DeadLetterNotice } from './DeadLetterNotice';
import { EmptyState } from './EmptyState';
import { FileBrowserActions } from './FileBrowserActions';
import { QueueHoldNotice } from './QueueHoldNotice';
import { UploadPanel } from './UploadPanel';

/** The vault browser: where you are, what is in it, and how to move. */
export function FileBrowser() {
  const { rows, folder, breadcrumbs, isLoading, isRoot, error, navigateTo, navigateUp } =
    useFolderNavigation();
  const { view } = useSnapshot();
  const store = useSnapshotStore();
  // A recoverable refusal clears on its own, so it renders over the listing it
  // interrupted; anything else is a verdict and blanks it.
  const recoverable = error !== null && isRecoverable(error) ? error : null;
  const settled = !isLoading && (error === null || (recoverable !== null && folder !== null));
  // A received share is grafted in with no parent link, so the engine refuses
  // every write under it at the journal call, whatever the grant permits. Until
  // the write plane can author there, only this vault's own scope gets a write
  // affordance — `view.permission` reports the grant and does not decide this.
  const writable = view !== null && view !== undefined && !view.receivedShare;

  return (
    <div className="file-browser" data-testid="file-browser">
      <Breadcrumbs crumbs={breadcrumbs} onNavigate={navigateTo} />
      <DeadLetterNotice deadLetters={view?.deadLetters ?? []} />
      <QueueHoldNotice view={view} />
      {recoverable !== null && (
        <div className="file-browser-notice" role="status" data-testid="file-browser-notice">
          <span className="file-browser-notice-message">{recoverable.message}</span>
          <button
            type="button"
            className="file-browser-notice-retry"
            onClick={() => store.refresh()}
          >
            [retry]
          </button>
        </div>
      )}
      {error !== null && recoverable === null && (
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
      <UploadPanel folder={settled && writable ? folder : null} />
      {settled && !writable && (
        <p className="file-browser-notice" role="status" data-testid="read-only-scope">
          this folder was shared with you. you can open and download what is in it. changes to a
          shared folder are not supported yet.
        </p>
      )}
      {settled && (
        <FileBrowserActions
          rows={rows}
          folder={folder}
          writable={writable}
          showParentRow={!isRoot}
          onOpen={navigateTo}
          onNavigateUp={navigateUp}
        />
      )}
      {settled && rows.length === 0 && <EmptyState />}
    </div>
  );
}
