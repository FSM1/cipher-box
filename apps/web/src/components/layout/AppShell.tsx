import type { ReactNode } from 'react';
import { StagingBanner } from '../StagingBanner';
import { AppFooter } from './AppFooter';
import { AppHeader } from './AppHeader';
import { AppSidebar } from './AppSidebar';

interface AppShellProps {
  children: ReactNode;
}

/** The signed-in frame: header, sidebar, scrollable main, footer. */
export function AppShell({ children }: AppShellProps) {
  return (
    <div className="app-frame">
      <StagingBanner />
      <div className="app-shell" data-testid="app-shell">
        <AppHeader />
        <AppSidebar />
        <main className="app-main">{children}</main>
        <AppFooter />
      </div>
    </div>
  );
}
