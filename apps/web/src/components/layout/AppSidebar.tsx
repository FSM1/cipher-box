/**
 * App sidebar component.
 * Contains navigation items and storage quota.
 */
export function AppSidebar() {
  return (
    <aside className="app-sidebar" data-testid="app-sidebar">
      <nav className="sidebar-nav">{/* NavItems will be added in Task 3 */}</nav>
      <div className="sidebar-footer">{/* StorageQuota will be added in Task 3 */}</div>
    </aside>
  );
}
