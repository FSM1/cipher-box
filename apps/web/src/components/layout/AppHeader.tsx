import { UserMenu } from './UserMenu';

interface AppHeaderProps {
  onSearchClick?: () => void;
}

/**
 * App header component.
 * Contains logo, search button, and user menu dropdown.
 */
export function AppHeader({ onSearchClick }: AppHeaderProps) {
  return (
    <header className="app-header" data-testid="app-header">
      <div className="header-left">
        <span className="header-prompt">&gt;</span>
        <span className="header-logo">CIPHERBOX</span>
      </div>
      <div className="header-right">
        {onSearchClick && (
          <button
            className="header-search-btn"
            onClick={onSearchClick}
            aria-label="Search files (Cmd+K)"
            title="Search (Cmd+K)"
            type="button"
          >
            {'>_'} <kbd>K</kbd>
          </button>
        )}
        <UserMenu />
      </div>
    </header>
  );
}
