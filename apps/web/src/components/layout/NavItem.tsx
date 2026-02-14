import { Link } from 'react-router-dom';

interface NavItemProps {
  to: string;
  icon: 'folder' | 'settings';
  label: string;
  active: boolean;
}

/**
 * Navigation item component.
 * Renders a sidebar navigation link with emoji icon.
 */
export function NavItem({ to, icon, label, active }: NavItemProps) {
  // Emoji icons per design specification
  const iconEmoji = icon === 'folder' ? '📁' : '⚙';

  const className = active ? 'nav-item nav-item--active' : 'nav-item';

  return (
    <Link to={to} className={className} data-testid={`nav-item-${label.toLowerCase()}`}>
      <span className="nav-item-icon">{iconEmoji}</span>
      <span className="nav-item-label">{label}</span>
    </Link>
  );
}
