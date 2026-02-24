import { UserMenu } from './UserMenu';

interface AppHeaderProps {
  onSearchClick?: () => void;
}

const isMac = typeof navigator !== 'undefined' && /Mac/i.test(navigator.platform);
const shortcutLabel = isMac ? '⌘K' : 'Ctrl+K';

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
            aria-label={`Search files (${shortcutLabel})`}
            title={`Search (${shortcutLabel})`}
            type="button"
          >
            {'>_'} <kbd>{shortcutLabel}</kbd>
          </button>
        )}
        <UserMenu />
      </div>
    </header>
  );
}
