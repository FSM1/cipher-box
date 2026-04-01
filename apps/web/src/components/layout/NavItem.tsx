import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

interface NavItemProps {
  to: string;
  icon: 'folder' | 'shared' | 'bin' | 'settings';
  label: string;
  active: boolean;
}

const ICON_MAP: Record<NavItemProps['icon'], ReactNode> = {
  folder: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path
        d="M1.5 2.5h4l1.5 1.5h7.5v9h-13v-10.5z"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeLinejoin="round"
      />
    </svg>
  ),
  shared: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M6.5 9.5l3-3" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <path
        d="M8.5 10.5l-1 1a2.12 2.12 0 01-3 0v0a2.12 2.12 0 010-3l1-1"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeLinecap="round"
      />
      <path
        d="M7.5 5.5l1-1a2.12 2.12 0 013 0v0a2.12 2.12 0 010 3l-1 1"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeLinecap="round"
      />
    </svg>
  ),
  bin: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path
        d="M3 4.5h10M6.5 4.5V3a.5.5 0 01.5-.5h2a.5.5 0 01.5.5v1.5M4 4.5l.5 8.5a1 1 0 001 1h5a1 1 0 001-1l.5-8.5"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  ),
  settings: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <circle cx="8" cy="8" r="2" stroke="currentColor" strokeWidth="1.2" />
      <path
        d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.05 3.05l1.06 1.06M11.89 11.89l1.06 1.06M3.05 12.95l1.06-1.06M11.89 4.11l1.06-1.06"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeLinecap="round"
      />
    </svg>
  ),
};

/**
 * Navigation item component.
 * Renders a sidebar navigation link with SVG icon.
 */
export function NavItem({ to, icon, label, active }: NavItemProps) {
  const className = active ? 'nav-item nav-item--active' : 'nav-item';

  return (
    <Link to={to} className={className} data-testid={`nav-item-${label.toLowerCase()}`}>
      <span className="nav-item-icon">{ICON_MAP[icon]}</span>
      <span className="nav-item-label">{label}</span>
    </Link>
  );
}
