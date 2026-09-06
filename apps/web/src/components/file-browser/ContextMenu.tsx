import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Portal } from '../ui/Portal';

/** Keeps the menu off the viewport edges when it opens near one. */
const EDGE_GAP = 8;

export interface ContextMenuItem {
  label: string;
  onSelect: () => void;
  destructive?: boolean;
}

interface ContextMenuProps {
  /** Viewport x the menu's own right edge is placed on. */
  right: number;
  top: number;
  label: string;
  items: ContextMenuItem[];
  onClose: () => void;
}

export function ContextMenu({ right, top, label, items, onClose }: ContextMenuProps) {
  const menuRef = useRef<HTMLDivElement>(null);
  const opener = useRef<Element | null>(null);
  const [position, setPosition] = useState({ left: right, top });

  const stops = useCallback(
    () => [...(menuRef.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? [])],
    []
  );

  // The menu is portalled out of the row, so Tab order never reaches it; it has
  // to take focus on open and give it back when it closes.
  useEffect(() => {
    opener.current = document.activeElement;
    stops()[0]?.focus();
    return () => {
      if (opener.current instanceof HTMLElement) opener.current.focus();
    };
  }, [stops]);

  useLayoutEffect(() => {
    const menu = menuRef.current;
    if (menu === null) return;
    const { width, height } = menu.getBoundingClientRect();
    const nextLeft = clamp(right - width, window.innerWidth - width);
    const nextTop = clamp(top, window.innerHeight - height);
    setPosition((current) =>
      current.left === nextLeft && current.top === nextTop
        ? current
        : { left: nextLeft, top: nextTop }
    );
  }, [right, top]);

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
        onKeyDown={(event) => {
          if (event.key === 'Tab') {
            event.preventDefault();
            onClose();
            return;
          }
          const focusable = stops();
          const at = focusable.indexOf(document.activeElement as HTMLElement);
          const next = step(event.key, at, focusable.length);
          if (next === null) return;
          event.preventDefault();
          focusable[next]?.focus();
        }}
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

/** Holds one axis inside the viewport, `limit` being the largest fitting start. */
function clamp(at: number, limit: number): number {
  return Math.max(EDGE_GAP, Math.min(at, limit - EDGE_GAP));
}

/** The menu roving-focus model: where a key moves focus, or `null` to ignore it. */
function step(key: string, at: number, count: number): number | null {
  if (count === 0) return null;
  if (key === 'ArrowDown') return (at + 1) % count;
  if (key === 'ArrowUp') return (at <= 0 ? count : at) - 1;
  if (key === 'Home') return 0;
  if (key === 'End') return count - 1;
  return null;
}
