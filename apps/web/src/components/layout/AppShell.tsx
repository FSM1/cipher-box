import { ReactNode } from 'react';
import { StagingBanner } from '../StagingBanner';
import { MatrixBackground } from '../MatrixBackground';
import { useAnyModalOpen } from '../../hooks/useModalOpen';
import { AppHeader } from './AppHeader';
import { AppSidebar } from './AppSidebar';
import { AppFooter } from './AppFooter';
import { DeviceApprovalModal } from '../mfa/DeviceApprovalModal';
import { MfaEnrollmentPrompt } from '../mfa/MfaEnrollmentPrompt';
import '../../styles/layout.css';

interface AppShellProps {
  children: ReactNode;
}

/**
 * App shell layout component.
 * Provides the fixed layout structure with header, sidebar, footer,
 * and a scrollable main content area.
 *
 * Also mounts cross-device approval modal and MFA enrollment prompt
 * so they appear regardless of which authenticated page the user is on.
 */
export function AppShell({ children }: AppShellProps) {
  const isStaging = import.meta.env.VITE_ENVIRONMENT === 'staging';
  const anyModalOpen = useAnyModalOpen();

  if (isStaging) {
    return (
      <div
        style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}
      >
        <StagingBanner variant="compact" />
        <div className="app-shell" data-testid="app-shell" style={{ height: 'auto', flex: 1 }}>
          <MatrixBackground paused={anyModalOpen} frameInterval={50} />
          <AppHeader />
          <MfaEnrollmentPrompt />
          <AppSidebar />
          <main className="app-main">{children}</main>
          <AppFooter />
          <DeviceApprovalModal />
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell" data-testid="app-shell">
      <MatrixBackground paused={anyModalOpen} frameInterval={50} />
      <AppHeader />
      <MfaEnrollmentPrompt />
      <AppSidebar />
      <main className="app-main">{children}</main>
      <AppFooter />
      <DeviceApprovalModal />
    </div>
  );
}
