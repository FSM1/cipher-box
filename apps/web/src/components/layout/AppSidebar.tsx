import { useLocation } from 'react-router-dom';
import { NavItem } from './NavItem';

/** Vault navigation. Only `/files` is served in this build; the rest is coming soon. */
export function AppSidebar() {
  const { pathname } = useLocation();

  return (
    <aside className="app-sidebar" data-testid="app-sidebar">
      <nav className="sidebar-nav">
        <NavItem to="/files" icon="folder" label="Files" active={pathname.startsWith('/files')} />
        <NavItem to="/shared" icon="shared" label="Shared" active={false} comingSoon />
        <NavItem to="/bin" icon="bin" label="Bin" active={false} comingSoon />
        <NavItem to="/settings" icon="settings" label="Settings" active={false} comingSoon />
      </nav>
    </aside>
  );
}
