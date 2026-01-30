import { Link } from 'react-router-dom';

interface NavItemProps {
  to: string;
  icon: 'folder' | 'settings';
  label: string;
  active: boolean;
}

/**
 * Navigation item component.
 * Renders a sidebar navigation link with terminal-style icon prefix.
 */
export function NavItem({ to, icon, label, active }: NavItemProps) {
  // Terminal-style ASCII icons
  const iconText = icon === 'folder' ? '[DIR]' : '[CFG]';

  const className = active ? 'nav-item nav-item--active' : 'nav-item';

  return (
    <Link to={to} className={className} data-testid={`nav-item-${label.toLowerCase()}`}>
      <span className="nav-item-icon">{iconText}</span>
      <span className="nav-item-label">{label}</span>
    </Link>
  );
}
