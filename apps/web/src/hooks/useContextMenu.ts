import { useState, useCallback } from 'react';
import type { FolderChildV2 } from '@cipherbox/crypto';

/**
 * Context menu state shape.
 */
type ContextMenuState = {
  visible: boolean;
  x: number;
  y: number;
  item: FolderChildV2 | null;
};

/**
 * Hook for managing context menu state.
 *
 * Provides show/hide functionality with position and item tracking.
 *
 * @example
 * ```tsx
 * function FileList() {
 *   const contextMenu = useContextMenu();
 *
 *   const handleContextMenu = (e: MouseEvent, item: FolderChildV2) => {
 *     contextMenu.show(e, item);
 *   };
 *
 *   return (
 *     <>
 *       {contextMenu.visible && (
 *         <ContextMenu
 *           x={contextMenu.x}
 *           y={contextMenu.y}
 *           item={contextMenu.item!}
 *           onClose={contextMenu.hide}
 *         />
 *       )}
 *     </>
 *   );
 * }
 * ```
 */
export function useContextMenu() {
  const [state, setState] = useState<ContextMenuState>({
    visible: false,
    x: 0,
    y: 0,
    item: null,
  });

  /**
   * Show context menu at the event position for the given item.
   */
  const show = useCallback((event: React.MouseEvent, item: FolderChildV2) => {
    event.preventDefault();
    event.stopPropagation();
    setState({
      visible: true,
      x: event.clientX,
      y: event.clientY,
      item,
    });
  }, []);

  /**
   * Hide the context menu.
   */
  const hide = useCallback(() => {
    setState((prev) => ({
      ...prev,
      visible: false,
    }));
  }, []);

  return {
    visible: state.visible,
    x: state.x,
    y: state.y,
    item: state.item,
    show,
    hide,
  };
}
