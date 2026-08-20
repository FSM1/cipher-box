import { useEngineAccount } from '../engine/useEngineSession';
import { FileBrowser } from '../components/file-browser/FileBrowser';
import { AppShell } from '../components/layout/AppShell';

/** The vault browser, behind `RequireAuth`. */
export function FilesPage() {
  return (
    <AppShell>
      {useEngineAccount() !== null ? (
        <FileBrowser />
      ) : (
        <p className="file-browser-loading" data-testid="files-signing-in">
          {'// CHECKING SESSION...'}
        </p>
      )}
    </AppShell>
  );
}
