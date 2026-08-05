import { createPortal } from 'react-dom';
import type { ReactNode } from 'react';

/** Renders children under `document.body`, clear of the browser's clipping. */
export function Portal({ children }: { children: ReactNode }) {
  return createPortal(children, document.body);
}
