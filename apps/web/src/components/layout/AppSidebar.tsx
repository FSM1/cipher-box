import { useLocation } from 'react-router-dom';
import { NavItem } from './NavItem';
import { StorageQuota } from './StorageQuota';

/**
 * App sidebar component.
 * Contains navigation items and storage quota indicator.
 */
export function AppSidebar() {
  const location = useLocation();

  return (
    <aside className="app-sidebar" data-testid="app-sidebar">
      <nav className="sidebar-nav">
        <NavItem
          to="/files"
          icon="folder"
          label="Files"
          active={location.pathname.startsWith('/files')}
        />
        <NavItem
          to="/shared"
          icon="shared"
          label="Shared"
          active={location.pathname.startsWith('/shared')}
        />
        <NavItem
          to="/settings"
          icon="settings"
          label="Settings"
          active={location.pathname === '/settings'}
        />
      </nav>
      <div className="sidebar-footer">
        <StorageQuota />
      </div>
    </aside>
  );
}
