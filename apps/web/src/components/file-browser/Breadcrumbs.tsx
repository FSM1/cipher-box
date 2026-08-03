import { Fragment } from 'react';
import type { BreadcrumbDescriptor } from '@cipherbox/client';
import { toHex } from '@cipherbox/client';

interface BreadcrumbsProps {
  /** Root-first trail, ending at the folder on screen. */
  crumbs: BreadcrumbDescriptor[];
  onNavigate: (node: Uint8Array) => void;
}

/** The vault's current location as a terminal path: `~/root/documents`. */
export function Breadcrumbs({ crumbs, onNavigate }: BreadcrumbsProps) {
  return (
    <nav className="breadcrumb-nav" aria-label="Current location" data-testid="breadcrumbs">
      <span className="breadcrumb-prefix">~</span>
      {crumbs.map((crumb, index) => {
        const isCurrent = index === crumbs.length - 1;
        return (
          <Fragment key={toHex(crumb.id)}>
            <span className="breadcrumb-separator">/</span>
            <button
              type="button"
              className={isCurrent ? 'breadcrumb-item breadcrumb-item--current' : 'breadcrumb-item'}
              onClick={() => onNavigate(crumb.id)}
              aria-current={isCurrent ? 'page' : undefined}
            >
              {/* The vault root carries no name of its own. */}
              {crumb.name === '' ? 'root' : crumb.name}
            </button>
          </Fragment>
        );
      })}
    </nav>
  );
}
