import { Link } from 'react-router-dom';

interface NavItemProps {
  to: string;
  icon: 'folder' | 'shared' | 'settings';
  label: string;
  active: boolean;
}

const ICON_MAP: Record<NavItemProps['icon'], string> = {
  folder: '\uD83D\uDCC1',
  shared: '\uD83D\uDD17',
  settings: '\u2699',
};

/**
 * Navigation item component.
 * Renders a sidebar navigation link with emoji icon.
 */
export function NavItem({ to, icon, label, active }: NavItemProps) {
  const iconEmoji = ICON_MAP[icon];

  const className = active ? 'nav-item nav-item--active' : 'nav-item';

  return (
    <Link to={to} className={className} data-testid={`nav-item-${label.toLowerCase()}`}>
      <span className="nav-item-icon">{iconEmoji}</span>
      <span className="nav-item-label">{label}</span>
    </Link>
  );
}
