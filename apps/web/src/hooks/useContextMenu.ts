import { useCallback, useState } from 'react';
import type { MouseEvent } from 'react';
import type { ListingRow } from '../vault/listing';

/** The row the menu acts on, and the row edges it hangs from: right and bottom. */
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
      const target = event.currentTarget;
      const anchor = (target.closest('[role="row"]') ?? target).getBoundingClientRect();
      setState({ row, right: anchor.right, top: anchor.bottom });
    }, []),
    close: useCallback(() => setState(null), []),
  };
}
