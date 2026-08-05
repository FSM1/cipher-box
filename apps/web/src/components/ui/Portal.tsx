import { createPortal } from 'react-dom';
import type { ReactNode } from 'react';

/** Renders children under `document.body`, clear of the browser's clipping. */
export function Portal({ children }: { children: ReactNode }) {
  if (typeof document === 'undefined') return null;
  return createPortal(children, document.body);
}
