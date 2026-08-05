import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Portal } from '../ui/Portal';

/** Keeps the menu off the viewport edges when it opens near one. */
const EDGE_GAP = 8;

export interface ContextMenuItem {
  label: string;
  onSelect: () => void;
  destructive?: boolean;
}

interface ContextMenuProps {
  x: number;
  y: number;
  label: string;
  items: ContextMenuItem[];
  onClose: () => void;
}

export function ContextMenu({ x, y, label, items, onClose }: ContextMenuProps) {
  const menuRef = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState({ left: x, top: y });

  useLayoutEffect(() => {
    const menu = menuRef.current;
    if (menu === null) return;
    const { width, height } = menu.getBoundingClientRect();
    const left = Math.max(EDGE_GAP, Math.min(x, window.innerWidth - width - EDGE_GAP));
    const top = Math.max(EDGE_GAP, Math.min(y, window.innerHeight - height - EDGE_GAP));
    setPosition((current) =>
      current.left === left && current.top === top ? current : { left, top }
    );
  }, [x, y]);

  useEffect(() => {
    const onPointerDown = (event: MouseEvent) => {
      if (!menuRef.current?.contains(event.target as Node)) onClose();
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('mousedown', onPointerDown, true);
    document.addEventListener('keydown', onKeyDown);
    window.addEventListener('resize', onClose);
    return () => {
      document.removeEventListener('mousedown', onPointerDown, true);
      document.removeEventListener('keydown', onKeyDown);
      window.removeEventListener('resize', onClose);
    };
  }, [onClose]);

  return (
    <Portal>
      <div
        ref={menuRef}
        className="context-menu"
        style={{ left: position.left, top: position.top }}
        role="menu"
        aria-label={label}
        data-testid="context-menu"
      >
        {items.map((item) => (
          <button
            key={item.label}
            type="button"
            role="menuitem"
            className={`context-menu-item${item.destructive ? ' context-menu-item--danger' : ''}`}
            onClick={() => {
              onClose();
              item.onSelect();
            }}
          >
            {item.label}
          </button>
        ))}
      </div>
    </Portal>
  );
}
