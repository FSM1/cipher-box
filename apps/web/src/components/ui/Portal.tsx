import { ReactNode } from 'react';
import { createPortal } from 'react-dom';

type PortalProps = {
  children: ReactNode;
  container?: Element | null;
};

/**
 * Portal component that renders children outside the component tree.
 * Useful for modals, tooltips, and overlays that need to escape parent styling.
 */
export function Portal({ children, container }: PortalProps) {
  const target = container ?? (typeof document !== 'undefined' ? document.body : null);

  if (!target) {
    return null;
  }

  return createPortal(children, target);
}
