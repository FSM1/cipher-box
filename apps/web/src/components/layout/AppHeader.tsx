import { UserMenu } from './UserMenu';

/**
 * App header component.
 * Contains logo and user menu dropdown.
 */
export function AppHeader() {
  return (
    <header className="app-header" data-testid="app-header">
      <div className="header-left">
        <span className="header-prompt">&gt;</span>
        <span className="header-logo">CIPHERBOX</span>
      </div>
      <div className="header-right">
        <UserMenu />
      </div>
    </header>
  );
}
