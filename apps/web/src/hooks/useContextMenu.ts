import { useCallback, useState } from 'react';
import type { MouseEvent } from 'react';
import type { ListingRow } from '../vault/listing';

/** Where the menu is anchored and which row it acts on. */
export interface ContextMenuState {
  row: ListingRow;
  x: number;
  y: number;
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
      // A keyboard activation carries no pointer position, so the menu anchors
      // to the control rather than the viewport corner.
      const anchor = event.detail === 0 ? event.currentTarget.getBoundingClientRect() : null;
      setState({
        row,
        x: anchor === null ? event.clientX : anchor.left,
        y: anchor === null ? event.clientY : anchor.bottom,
      });
    }, []),
    close: useCallback(() => setState(null), []),
  };
}
