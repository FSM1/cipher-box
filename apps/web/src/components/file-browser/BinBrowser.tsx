/**
 * BinBrowser -- Recycle bin browser with flat list of deleted items.
 *
 * Shows all soft-deleted files and folders in a flat list sorted by deletion date.
 * Supports restore, permanent delete, batch operations, and Empty Bin.
 * Auto-purges expired items on mount.
 */

import { useState, useCallback, useEffect, useRef, useMemo, type MouseEvent } from 'react';
import type { BinEntry } from '@cipherbox/core';
import { useBin } from '../../hooks/useBin';
import { useRestoreStore } from '../../stores/restore.store';
import { BinListItem } from './BinListItem';
import { BinEmptyState } from './BinEmptyState';
import { ConfirmDialog } from './ConfirmDialog';
import '../../styles/bin-browser.css';
import { logger } from '../../lib/logger';

type SortField = 'name' | 'deletedAt' | 'size' | 'daysRemaining';
type SortDirection = 'asc' | 'desc';

export function BinBrowser() {
  const {
    entries,
    isLoading,
    isLoaded,
    error,
    retentionDays,
    daysRemaining,
    loadBin,
    restore,
    permanentDelete,
    emptyAll,
    restoreMultiple,
    permanentDeleteMultiple,
    isLoading: isOperating,
  } = useBin();

  // Restore status affordance (D-05) — driven by useBin.restore/restoreMultiple,
  // which write to useRestoreStore. Subscribe here so the in-flight restore is
  // visible; the store is a metadata-only status machine (no byte stream).
  const restoreStatus = useRestoreStore((s) => s.status);
  const restoreItem = useRestoreStore((s) => s.currentItem);
  const restoreError = useRestoreStore((s) => s.error);
  const resetRestore = useRestoreStore((s) => s.resetRestore);

  // Clear any stale restore status on mount, and reset again on unmount so a
  // finished restore never lingers when the bin is reopened.
  useEffect(() => {
    resetRestore();
    return () => resetRestore();
  }, [resetRestore]);

  // Auto-clear the terminal (success/error) status after a brief flash so the
  // affordance does not stick around once entries have refreshed.
  useEffect(() => {
    if (restoreStatus !== 'success' && restoreStatus !== 'error') return;
    const timer = setTimeout(() => resetRestore(), 2500);
    return () => clearTimeout(timer);
  }, [restoreStatus, resetRestore]);

  // Sort state
  const [sortField, setSortField] = useState<SortField>('deletedAt');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const lastSelectedIdRef = useRef<string | null>(null);
  const contextMenuRef = useRef<HTMLDivElement>(null);

  // Confirmation dialog state
  const [confirmDialog, setConfirmDialog] = useState<{
    open: boolean;
    title: string;
    message: string;
    confirmLabel: string;
    onConfirm: () => void;
  }>({ open: false, title: '', message: '', confirmLabel: '', onConfirm: () => {} });

  // Context menu state
  const [contextMenu, setContextMenu] = useState<{
    visible: boolean;
    x: number;
    y: number;
    entry: BinEntry | null;
  }>({ visible: false, x: 0, y: 0, entry: null });

  // Load bin on mount
  useEffect(() => {
    void loadBin();
  }, [loadBin]);

  // Prune stale selectedIds when entries change
  const entryIds = useMemo(() => new Set(entries.map((e) => e.id)), [entries]);
  useEffect(() => {
    setSelectedIds((prev) => {
      if (prev.size === 0) return prev;
      const pruned = new Set([...prev].filter((id) => entryIds.has(id)));
      if (pruned.size === prev.size) return prev;
      return pruned;
    });
  }, [entryIds]);

  // Sort entries
  const sortedEntries = useMemo(() => {
    const sorted = [...entries].sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'name':
          cmp = a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
          break;
        case 'deletedAt':
          cmp = a.deletedAt - b.deletedAt;
          break;
        case 'size':
          cmp = a.size - b.size;
          break;
        case 'daysRemaining':
          cmp = daysRemaining(a) - daysRemaining(b);
          break;
      }
      return sortDirection === 'asc' ? cmp : -cmp;
    });
    return sorted;
  }, [entries, sortField, sortDirection, daysRemaining]);

  // Toggle sort column
  const handleSortClick = useCallback(
    (field: SortField) => {
      if (sortField === field) {
        setSortDirection((prev) => (prev === 'asc' ? 'desc' : 'asc'));
      } else {
        setSortField(field);
        setSortDirection(field === 'name' ? 'asc' : 'desc');
      }
    },
    [sortField]
  );

  // Sort indicator
  const sortIndicator = (field: SortField) => {
    if (sortField !== field) return '';
    return sortDirection === 'asc' ? ' ^' : ' v';
  };

  // Selection handlers
  const handleSelect = useCallback(
    (entryId: string, event: { ctrlKey: boolean; shiftKey: boolean; metaKey: boolean }) => {
      const isCtrl = event.ctrlKey || event.metaKey;
      const isShift = event.shiftKey;

      if (isShift && lastSelectedIdRef.current) {
        const ids = sortedEntries.map((e) => e.id);
        const startIdx = ids.indexOf(lastSelectedIdRef.current);
        const endIdx = ids.indexOf(entryId);
        if (startIdx !== -1 && endIdx !== -1) {
          const rangeStart = Math.min(startIdx, endIdx);
          const rangeEnd = Math.max(startIdx, endIdx);
          const rangeIds = ids.slice(rangeStart, rangeEnd + 1);
          setSelectedIds((prev) => {
            const next = new Set(prev);
            for (const id of rangeIds) next.add(id);
            return next;
          });
          lastSelectedIdRef.current = entryId;
        } else {
          // Stale anchor — fall back to selecting the clicked row
          setSelectedIds(new Set([entryId]));
          lastSelectedIdRef.current = entryId;
        }
      } else if (isCtrl) {
        setSelectedIds((prev) => {
          const next = new Set(prev);
          if (next.has(entryId)) next.delete(entryId);
          else next.add(entryId);
          return next;
        });
        lastSelectedIdRef.current = entryId;
      } else {
        setSelectedIds(new Set([entryId]));
        lastSelectedIdRef.current = entryId;
      }
    },
    [sortedEntries]
  );

  const clearSelection = useCallback(() => {
    setSelectedIds(new Set());
    lastSelectedIdRef.current = null;
  }, []);

  // Context menu handlers
  const handleContextMenu = useCallback(
    (event: MouseEvent, entry: BinEntry) => {
      event.preventDefault();
      // If right-clicked entry is not selected, select only that entry
      if (!selectedIds.has(entry.id)) {
        setSelectedIds(new Set([entry.id]));
        lastSelectedIdRef.current = entry.id;
      }
      setContextMenu({ visible: true, x: event.clientX, y: event.clientY, entry });
    },
    [selectedIds]
  );

  const hideContextMenu = useCallback(() => {
    setContextMenu({ visible: false, x: 0, y: 0, entry: null });
  }, []);

  // Close context menu on click outside or escape
  useEffect(() => {
    if (!contextMenu.visible) return;

    const handleClickOutside = (event: globalThis.MouseEvent) => {
      if (contextMenuRef.current && !contextMenuRef.current.contains(event.target as Node)) {
        hideContextMenu();
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') hideContextMenu();
    };

    document.addEventListener('mousedown', handleClickOutside, true);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside, true);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [contextMenu.visible, hideContextMenu]);

  // Action handlers
  const handleRestore = useCallback(
    async (entryId: string) => {
      try {
        await restore(entryId);
        clearSelection();
      } catch {
        logger.error('[Bin] Restore failed');
      }
    },
    [restore, clearSelection]
  );

  const handlePermanentDelete = useCallback(
    (entryId: string) => {
      const entry = entries.find((e) => e.id === entryId);
      const name = entry?.name ?? 'this item';
      setConfirmDialog({
        open: true,
        title: 'Delete Permanently?',
        message: `This will permanently delete "${name}". This cannot be undone.`,
        confirmLabel: 'Delete Permanently',
        onConfirm: async () => {
          try {
            await permanentDelete(entryId);
            clearSelection();
            setConfirmDialog((prev) => ({ ...prev, open: false }));
          } catch {
            logger.error('[Bin] Permanent delete failed');
          }
        },
      });
    },
    [entries, permanentDelete, clearSelection]
  );

  // Context menu actions
  const handleContextRestore = useCallback(() => {
    if (!contextMenu.entry) return;
    hideContextMenu();
    void handleRestore(contextMenu.entry.id);
  }, [contextMenu.entry, hideContextMenu, handleRestore]);

  const handleContextPermanentDelete = useCallback(() => {
    if (!contextMenu.entry) return;
    hideContextMenu();
    handlePermanentDelete(contextMenu.entry.id);
  }, [contextMenu.entry, hideContextMenu, handlePermanentDelete]);

  // Batch actions
  const handleBatchRestore = useCallback(async () => {
    if (selectedIds.size === 0) return;
    try {
      await restoreMultiple([...selectedIds]);
      clearSelection();
    } catch {
      logger.error('[Bin] Batch restore failed');
    }
  }, [selectedIds, restoreMultiple, clearSelection]);

  const handleBatchPermanentDelete = useCallback(() => {
    if (selectedIds.size === 0) return;
    const count = selectedIds.size;
    setConfirmDialog({
      open: true,
      title: `Delete ${count} Items Permanently?`,
      message: `This will permanently delete ${count} selected item${count !== 1 ? 's' : ''}. This cannot be undone.`,
      confirmLabel: 'Delete Permanently',
      onConfirm: async () => {
        try {
          await permanentDeleteMultiple([...selectedIds]);
          clearSelection();
          setConfirmDialog((prev) => ({ ...prev, open: false }));
        } catch {
          logger.error('[Bin] Batch permanent delete failed');
        }
      },
    });
  }, [selectedIds, permanentDeleteMultiple, clearSelection]);

  // Empty Bin
  const handleEmptyBin = useCallback(() => {
    const count = entries.length;
    setConfirmDialog({
      open: true,
      title: 'Empty Bin?',
      message: `This will permanently delete all ${count} item${count !== 1 ? 's' : ''} in the bin. This cannot be undone.`,
      confirmLabel: 'Empty Bin',
      onConfirm: async () => {
        try {
          await emptyAll();
          clearSelection();
          setConfirmDialog((prev) => ({ ...prev, open: false }));
        } catch {
          logger.error('[Bin] Empty bin failed');
        }
      },
    });
  }, [entries.length, emptyAll, clearSelection]);

  const closeConfirmDialog = useCallback(() => {
    setConfirmDialog((prev) => ({ ...prev, open: false }));
  }, []);

  const hasEntries = entries.length > 0;
  const multiSelectActive = selectedIds.size > 1;

  return (
    <div className="file-browser-content bin-browser">
      {/* Toolbar with title and Empty Bin */}
      <div className="file-browser-toolbar">
        <nav className="breadcrumb-nav" aria-label="Current location" data-testid="breadcrumbs">
          <span className="breadcrumb-prefix">~</span>
          <span className="breadcrumb-separator">/</span>
          <span className="breadcrumb-item breadcrumb-item--current" aria-current="page">
            bin
          </span>
        </nav>
        <div className="file-browser-actions">
          {hasEntries && (
            <button
              type="button"
              className="toolbar-btn toolbar-btn--destructive"
              onClick={handleEmptyBin}
              disabled={isOperating}
              aria-label="Empty bin"
              data-testid="empty-bin-btn"
            >
              {'// empty bin'}
            </button>
          )}
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="bin-error" role="alert">
          <span>
            {'// ERROR: '}
            {error}
          </span>
        </div>
      )}

      {/* Restore status affordance (D-05) */}
      {restoreStatus !== 'idle' && (
        <div
          className={`bin-restore-status bin-restore-status--${restoreStatus}`}
          role="status"
          aria-live="polite"
          data-testid="restore-status"
        >
          {restoreStatus === 'restoring' && (
            <span className="bin-restore-status-spinner" data-testid="restore-spinner">
              {`// restoring ${restoreItem ?? 'item'}...`}
            </span>
          )}
          {restoreStatus === 'success' && <span>{'// restore complete'}</span>}
          {restoreStatus === 'error' && (
            <span>
              {'// restore failed: '}
              {restoreError}
            </span>
          )}
        </div>
      )}

      {/* Loading state */}
      {isLoading && !isLoaded && (
        <div className="file-browser-loading">
          <span className="file-browser-loading-spinner">{'// loading bin...'}</span>
        </div>
      )}

      {/* Bin items list */}
      {isLoaded && hasEntries && (
        <div className="file-list bin-list" role="grid" data-testid="bin-list">
          {/* Column headers */}
          <div className="bin-list-header" role="row">
            <button
              type="button"
              className="bin-column-header bin-column-name"
              onClick={() => handleSortClick('name')}
              role="columnheader"
              aria-sort={
                sortField === 'name'
                  ? sortDirection === 'asc'
                    ? 'ascending'
                    : 'descending'
                  : 'none'
              }
            >
              {'[NAME]'}
              {sortIndicator('name')}
            </button>
            <div className="bin-column-header bin-column-path" role="columnheader">
              [LOCATION]
            </div>
            <button
              type="button"
              className="bin-column-header bin-column-deleted"
              onClick={() => handleSortClick('deletedAt')}
              role="columnheader"
              aria-sort={
                sortField === 'deletedAt'
                  ? sortDirection === 'asc'
                    ? 'ascending'
                    : 'descending'
                  : 'none'
              }
            >
              {'[DELETED]'}
              {sortIndicator('deletedAt')}
            </button>
            <button
              type="button"
              className="bin-column-header bin-column-size"
              onClick={() => handleSortClick('size')}
              role="columnheader"
              aria-sort={
                sortField === 'size'
                  ? sortDirection === 'asc'
                    ? 'ascending'
                    : 'descending'
                  : 'none'
              }
            >
              {'[SIZE]'}
              {sortIndicator('size')}
            </button>
            <button
              type="button"
              className="bin-column-header bin-column-remaining"
              onClick={() => handleSortClick('daysRemaining')}
              role="columnheader"
              aria-sort={
                sortField === 'daysRemaining'
                  ? sortDirection === 'asc'
                    ? 'ascending'
                    : 'descending'
                  : 'none'
              }
            >
              {'[TIME LEFT]'}
              {sortIndicator('daysRemaining')}
            </button>
          </div>

          {/* Item rows */}
          <div className="file-list-body" role="rowgroup">
            {sortedEntries.map((entry) => (
              <BinListItem
                key={entry.id}
                entry={entry}
                isSelected={selectedIds.has(entry.id)}
                daysLeft={daysRemaining(entry)}
                onSelect={handleSelect}
                onContextMenu={handleContextMenu}
              />
            ))}
          </div>
        </div>
      )}

      {/* Empty state */}
      {isLoaded && !hasEntries && <BinEmptyState retentionDays={retentionDays} />}

      {/* Selection action bar */}
      {multiSelectActive && (
        <div
          className="selection-action-bar bin-selection-bar"
          role="toolbar"
          aria-label="Bin selection actions"
        >
          <div className="selection-action-bar-info">
            <span className="selection-action-bar-count">
              {selectedIds.size} item{selectedIds.size !== 1 ? 's' : ''} selected
            </span>
            <button
              type="button"
              className="selection-action-bar-clear"
              onClick={clearSelection}
              aria-label="Clear selection"
            >
              [clear]
            </button>
          </div>
          <div className="selection-action-bar-actions">
            <button
              type="button"
              className="toolbar-btn toolbar-btn--secondary"
              onClick={handleBatchRestore}
              disabled={isOperating}
              aria-label={`Restore ${selectedIds.size} items`}
            >
              {'<- restore'}
            </button>
            <button
              type="button"
              className="toolbar-btn toolbar-btn--secondary selection-action-bar-delete"
              onClick={handleBatchPermanentDelete}
              disabled={isOperating}
              aria-label={`Delete ${selectedIds.size} items permanently`}
            >
              {'x delete permanently'}
            </button>
          </div>
        </div>
      )}

      {/* Context menu */}
      {contextMenu.visible && contextMenu.entry && (
        <div
          ref={contextMenuRef}
          className="context-menu bin-context-menu"
          style={{ position: 'fixed', left: contextMenu.x, top: contextMenu.y }}
          role="menu"
          aria-label={`Actions for ${contextMenu.entry.name}`}
          data-testid="bin-context-menu"
        >
          <button
            type="button"
            className="context-menu-item"
            onClick={handleContextRestore}
            role="menuitem"
          >
            <span className="context-menu-item-icon">{'<-'}</span>
            Restore
          </button>
          <div className="context-menu-divider" role="separator" />
          <button
            type="button"
            className="context-menu-item context-menu-item--destructive"
            onClick={handleContextPermanentDelete}
            role="menuitem"
          >
            <span className="context-menu-item-icon">&#128465;</span>
            Delete Permanently
          </button>
        </div>
      )}

      {/* Confirmation dialog */}
      <ConfirmDialog
        open={confirmDialog.open}
        onClose={closeConfirmDialog}
        onConfirm={confirmDialog.onConfirm}
        title={confirmDialog.title}
        message={confirmDialog.message}
        confirmLabel={confirmDialog.confirmLabel}
        isDestructive
        isLoading={isOperating}
      />
    </div>
  );
}
