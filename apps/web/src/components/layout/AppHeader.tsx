/**
 * App header component.
 * Contains logo and user menu.
 */
export function AppHeader() {
  return (
    <header className="app-header" data-testid="app-header">
      <div className="header-left">
        <span className="header-prompt">&gt;</span>
        <span className="header-logo">CIPHERBOX</span>
      </div>
      <div className="header-right">{/* UserMenu will be added in Task 2 */}</div>
    </header>
  );
}
