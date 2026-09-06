import { useCallback, useState } from 'react';
import type { MouseEvent } from 'react';
import type { ListingRow } from '../vault/listing';

/** The row the menu acts on, and the viewport point its top-right corner takes. */
export interface ContextMenuState {
  row: ListingRow;
  right: number;
  top: number;
}

export interface ContextMenu {
  state: ContextMenuState | null;
  open(event: MouseEvent<HTMLElement>, row: ListingRow): void;
  close(): void;
}

export function useContextMenu(): ContextMenu {
  const [state, setState] = useState<ContextMenuState | null>(null);

  return {
    state,
    open: useCallback((event: MouseEvent<HTMLElement>, row: ListingRow) => {
      event.preventDefault();
      const anchor = event.currentTarget.closest('[role="row"]');
      if (anchor === null) return;
      const box = anchor.getBoundingClientRect();
      setState({ row, right: box.right, top: box.bottom });
    }, []),
    close: useCallback(() => setState(null), []),
  };
}
