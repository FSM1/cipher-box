import { useState, useCallback } from 'react';

export type DialogState<T> = {
  open: boolean;
  item: T | null;
};

const CLOSED_STATE = { open: false, item: null } as const;

/**
 * Manage open/close state for a dialog that operates on an item.
 *
 * Returns a tuple of [state, open, close] where:
 * - state.open: whether the dialog is visible
 * - state.item: the item being operated on (null when closed)
 * - open(item): open the dialog for a given item
 * - close(): close the dialog and clear the item
 */
export function useDialogState<T>(): [DialogState<T>, (item: T) => void, () => void] {
  const [state, setState] = useState<DialogState<T>>(CLOSED_STATE);

  const open = useCallback((item: T) => {
    setState({ open: true, item });
  }, []);

  const close = useCallback(() => {
    setState(CLOSED_STATE);
  }, []);

  return [state, open, close];
}
