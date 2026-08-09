import type { ReactNode } from 'react';
import { useRefreshOnWake } from '../../engine/useRefreshOnWake';
import { NotificationToast } from '../NotificationToast';
import { StagingBanner } from '../StagingBanner';
import { AppFooter } from './AppFooter';
import { AppHeader } from './AppHeader';
import { AppSidebar } from './AppSidebar';
import { OfflineBanner } from './OfflineBanner';

interface AppShellProps {
  children: ReactNode;
}

/**
 * The signed-in frame: header, sidebar, scrollable main, footer, and the
 * cross-cutting chrome that renders event-stream state only
 * (blueprint/web-client.md "Composition").
 */
export function AppShell({ children }: AppShellProps) {
  useRefreshOnWake();

  return (
    <div className="app-frame">
      <StagingBanner />
      <OfflineBanner />
      <div className="app-shell" data-testid="app-shell">
        <AppHeader />
        <AppSidebar />
        <main className="app-main">{children}</main>
        <AppFooter />
      </div>
      <NotificationToast />
    </div>
  );
}
