import { ReactNode, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { StagingBanner } from '../StagingBanner';
import { MatrixBackground } from '../MatrixBackground';
import { useAnyModalOpen } from '../../hooks/useModalOpen';
import { useSearch } from '../../hooks/useSearch';
import { AppHeader } from './AppHeader';
import { AppSidebar } from './AppSidebar';
import { AppFooter } from './AppFooter';
import { SearchPalette } from '../file-browser/SearchPalette';
import { DeviceApprovalModal } from '../mfa/DeviceApprovalModal';
import { MfaEnrollmentPrompt } from '../mfa/MfaEnrollmentPrompt';
import { NotificationToast } from '../NotificationToast';
import type { SearchResult } from '../../services/search-index.service';
import '../../styles/layout.css';

interface AppShellProps {
  children: ReactNode;
}

/**
 * App shell layout component.
 * Provides the fixed layout structure with header, sidebar, footer,
 * and a scrollable main content area.
 *
 * Also mounts cross-device approval modal, MFA enrollment prompt,
 * and search palette overlay so they appear regardless of which
 * authenticated page the user is on.
 */
export function AppShell({ children }: AppShellProps) {
  const isStaging = import.meta.env.VITE_ENVIRONMENT === 'staging';
  const anyModalOpen = useAnyModalOpen();
  const search = useSearch();
  const navigate = useNavigate();

  const handleSelectResult = useCallback(
    (result: SearchResult) => {
      search.close();
      if (result.parentFolderId === 'root') {
        navigate('/files');
      } else {
        navigate(`/files/${result.parentFolderId}`);
      }
    },
    [search, navigate]
  );

  if (isStaging) {
    return (
      <div
        style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}
      >
        <StagingBanner variant="compact" />
        <div className="app-shell" data-testid="app-shell" style={{ height: 'auto', flex: 1 }}>
          <MatrixBackground paused={anyModalOpen} frameInterval={50} />
          <AppHeader onSearchClick={search.open} />
          <MfaEnrollmentPrompt />
          <AppSidebar />
          <main className="app-main">{children}</main>
          <AppFooter />
          <DeviceApprovalModal />
          <NotificationToast />
          <SearchPalette
            isOpen={search.isOpen}
            query={search.query}
            onQueryChange={search.setQuery}
            results={search.results}
            resultCount={search.resultCount}
            isBuilding={search.isBuilding}
            isIndexReady={search.isIndexReady}
            onClose={search.close}
            onSelectResult={handleSelectResult}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell" data-testid="app-shell">
      <MatrixBackground paused={anyModalOpen} frameInterval={50} />
      <AppHeader onSearchClick={search.open} />
      <MfaEnrollmentPrompt />
      <AppSidebar />
      <main className="app-main">{children}</main>
      <AppFooter />
      <DeviceApprovalModal />
      <NotificationToast />
      <SearchPalette
        isOpen={search.isOpen}
        query={search.query}
        onQueryChange={search.setQuery}
        results={search.results}
        resultCount={search.resultCount}
        isBuilding={search.isBuilding}
        isIndexReady={search.isIndexReady}
        onClose={search.close}
        onSelectResult={handleSelectResult}
      />
    </div>
  );
}
