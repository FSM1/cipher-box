import { useLocation } from 'react-router-dom';
import { NavItem } from './NavItem';

/** Vault navigation. */
export function AppSidebar() {
  const { pathname } = useLocation();

  return (
    <aside className="app-sidebar" data-testid="app-sidebar">
      <nav className="sidebar-nav">
        <NavItem to="/files" icon="folder" label="Files" active={pathname.startsWith('/files')} />
        <NavItem
          to="/shared"
          icon="shared"
          label="Shared"
          active={pathname.startsWith('/shared')}
        />
        <NavItem to="/bin" icon="bin" label="Bin" active={pathname.startsWith('/bin')} />
        <NavItem
          to="/settings"
          icon="settings"
          label="Settings"
          active={pathname.startsWith('/settings')}
        />
      </nav>
    </aside>
  );
}
