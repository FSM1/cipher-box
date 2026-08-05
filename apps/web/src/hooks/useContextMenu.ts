import { useCallback, useState } from 'react';
import type { ListingRow } from '../vault/listing';

/** Where the menu is anchored and which row it acts on. */
export interface ContextMenuState {
  row: ListingRow;
  x: number;
  y: number;
}

export interface ContextMenu {
  state: ContextMenuState | null;
  open(event: { clientX: number; clientY: number; preventDefault(): void }, row: ListingRow): void;
  close(): void;
}

export function useContextMenu(): ContextMenu {
  const [state, setState] = useState<ContextMenuState | null>(null);

  return {
    state,
    open: useCallback((event, row) => {
      event.preventDefault();
      setState({ row, x: event.clientX, y: event.clientY });
    }, []),
    close: useCallback(() => setState(null), []),
  };
}
