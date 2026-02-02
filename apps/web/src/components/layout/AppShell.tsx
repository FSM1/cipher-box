import { ReactNode } from 'react';
import { AppHeader } from './AppHeader';
import { AppSidebar } from './AppSidebar';
import { AppFooter } from './AppFooter';
import '../../styles/layout.css';

interface AppShellProps {
  children: ReactNode;
}

/**
 * App shell layout component.
 * Provides the fixed layout structure with header, sidebar, footer,
 * and a scrollable main content area.
 */
export function AppShell({ children }: AppShellProps) {
  return (
    <div className="app-shell" data-testid="app-shell">
      <AppHeader />
      <AppSidebar />
      <main className="app-main">{children}</main>
      <AppFooter />
    </div>
  );
}
