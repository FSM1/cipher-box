/**
 * useFileBrowserActions -- Handler logic for FileBrowser.
 *
 * Extracted from FileBrowser.tsx to separate handler logic from JSX.
 * Contains all useCallback handlers, dialog state, selection state,
 * and drag state management.
 */

import {
  useState,
  useCallback,
  useEffect,
  useRef,
  useMemo,
  type DragEvent,
  type MouseEvent,
} from 'react';
import type { FolderChild } from '@cipherbox/core';
import { useDialogState } from '../../hooks/useDialogState';
import {
  isFilePointer,
  isImageFile,
  isPdfFile,
  isAudioFile,
  isVideoFile,
} from '../../utils/fileTypes';
import { useFolderStore } from '../../stores/folder.store';
import { useSyncStore } from '../../stores/sync.store';
import { isExternalFileDrag } from '../../hooks/useDropUpload';
import { resolveIpnsRecord } from '../../services/ipns.service';
import { fetchAndDecryptMetadata } from '../../services/folder.service';
import { triggerSearchIndexRebuild } from '../../hooks/useSearch';
import { logger } from '../../lib/logger';

export type FileBrowserActionsParams = {
  currentFolderId: string;
  currentFolder: {
    children: FolderChild[];
    folderKey: Uint8Array;
  } | null;
  breadcrumbs: Array<{ id: string; name: string }>;
  navigateTo: (folderId: string) => void;
  navigateUp: () => void;
  createFolder: (name: string, parentFolderId: string | null) => Promise<{ ipnsName: string }>;
  renameItem: (
    itemId: string,
    itemType: 'file' | 'folder',
    newName: string,
    parentId: string,
  ) => Promise<void>;
  moveItem: (
    itemId: string,
    itemType: 'file' | 'folder',
    sourceParentId: string,
    destParentId: string,
  ) => Promise<void>;
  moveItems: (
    items: Array<{ id: string; type: 'file' | 'folder' }>,
    sourceParentId: string,
    destParentId: string,
  ) => Promise<void>;
  deleteItem: (itemId: string, itemType: 'file' | 'folder', parentId: string) => Promise<void>;
  deleteItems: (
    items: Array<{ id: string; type: 'file' | 'folder' }>,
    parentId: string,
  ) => Promise<void>;
  isOperating: boolean;
  isDownloading: boolean;
  downloadFromIpns: (params: {
    fileMetaIpnsName: string;
    folderKey: Uint8Array;
    fileName: string;
  }) => Promise<void>;
  handleFileDrop: (files: File[], folderId: string) => void;
  contextMenu: {
    visible: boolean;
    x: number;
    y: number;
    item: FolderChild | null;
    show: (event: MouseEvent, item: FolderChild) => void;
    hide: () => void;
  };
  rootIpnsName: string | null;
};

export function useFileBrowserActions(params: FileBrowserActionsParams) {
  const {
    currentFolderId,
    currentFolder,
    navigateTo,
    createFolder,
    renameItem,
    moveItem,
    moveItems,
    deleteItem,
    deleteItems,
    downloadFromIpns,
    handleFileDrop,
    contextMenu,
    rootIpnsName,
  } = params;

  const children = currentFolder?.children ?? [];

  // ---------------------------------------------------------------------------
  // Sync callback
  // ---------------------------------------------------------------------------

  const handleSync = useCallback(async () => {
    if (!rootIpnsName) return;

    const resolved = await resolveIpnsRecord(rootIpnsName);
    if (!resolved) return;

    const rootFolder = useFolderStore.getState().folders['root'];
    if (!rootFolder) return;

    if (resolved.sequenceNumber <= rootFolder.sequenceNumber) return;

    try {
      const metadata = await fetchAndDecryptMetadata(resolved.cid, rootFolder.folderKey);
      useFolderStore.getState().updateFolderChildren('root', metadata.children);
      useFolderStore.getState().updateFolderSequence('root', resolved.sequenceNumber);
      triggerSearchIndexRebuild();
    } catch (err) {
      logger.error('[FileBrowser] Sync refresh failed:', err);
      if (!useSyncStore.getState().initialSyncComplete) {
        throw err;
      }
    }
  }, [rootIpnsName]);

  // ---------------------------------------------------------------------------
  // Drag state
  // ---------------------------------------------------------------------------

  const [isDraggingExternal, setIsDraggingExternal] = useState(false);
  const dragCounterRef = useRef(0);

  const handleContentDragEnter = useCallback((e: DragEvent) => {
    if (isExternalFileDrag(e.dataTransfer)) {
      dragCounterRef.current += 1;
      if (dragCounterRef.current === 1) {
        setIsDraggingExternal(true);
      }
    }
  }, []);

  const handleContentDragOver = useCallback((e: DragEvent) => {
    if (isExternalFileDrag(e.dataTransfer)) {
      e.preventDefault();
      e.dataTransfer.dropEffect = 'copy';
    }
  }, []);

  const handleContentDragLeave = useCallback((e: DragEvent) => {
    if (isExternalFileDrag(e.dataTransfer)) {
      dragCounterRef.current -= 1;
      if (dragCounterRef.current <= 0) {
        dragCounterRef.current = 0;
        setIsDraggingExternal(false);
      }
    }
  }, []);

  useEffect(() => {
    const resetDragState = () => {
      dragCounterRef.current = 0;
      setIsDraggingExternal(false);
    };
    const handleWindowDrop = (e: Event) => {
      e.preventDefault();
      resetDragState();
    };
    const handleWindowDragLeave = (e: globalThis.DragEvent) => {
      if (!e.relatedTarget) resetDragState();
    };
    window.addEventListener('dragend', resetDragState);
    window.addEventListener('drop', handleWindowDrop);
    window.addEventListener('dragleave', handleWindowDragLeave as EventListener);
    return () => {
      window.removeEventListener('dragend', resetDragState);
      window.removeEventListener('drop', handleWindowDrop);
      window.removeEventListener('dragleave', handleWindowDragLeave as EventListener);
    };
  }, []);

  const handleContentDrop = useCallback(
    (e: DragEvent) => {
      dragCounterRef.current = 0;
      setIsDraggingExternal(false);
      if (!e.dataTransfer.files || e.dataTransfer.files.length === 0) return;
      if (!isExternalFileDrag(e.dataTransfer)) return;
      e.preventDefault();
      const files = Array.from(e.dataTransfer.files);
      handleFileDrop(files, currentFolderId);
    },
    [handleFileDrop, currentFolderId],
  );

  const handleExternalFileDrop = useCallback(
    (files: File[], targetFolderId: string) => {
      dragCounterRef.current = 0;
      setIsDraggingExternal(false);
      handleFileDrop(files, targetFolderId);
    },
    [handleFileDrop],
  );

  // ---------------------------------------------------------------------------
  // Selection state
  // ---------------------------------------------------------------------------

  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const lastSelectedIdRef = useRef<string | null>(null);

  const childIds = useMemo(() => new Set(children.map((c) => c.id)), [children]);
  useEffect(() => {
    setSelectedIds((prev) => {
      if (prev.size === 0) return prev;
      const pruned = new Set([...prev].filter((id) => childIds.has(id)));
      if (pruned.size === prev.size) return prev;
      return pruned;
    });
  }, [childIds]);

  const selectedItems = useMemo(
    () => children.filter((c) => selectedIds.has(c.id)),
    [children, selectedIds],
  );
  const multiSelectActive = selectedIds.size > 0;

  // ---------------------------------------------------------------------------
  // Dialog states
  // ---------------------------------------------------------------------------

  const [confirmDialog, openConfirmDialog, closeConfirmDialog] = useDialogState<FolderChild>();
  const [renameDialog, openRenameDialog, closeRenameDialog] = useDialogState<FolderChild>();
  const [moveDialog, openMoveDialog, closeMoveDialog] = useDialogState<FolderChild>();
  const [detailsDialog, openDetailsDialog, closeDetailsDialog] = useDialogState<FolderChild>();
  const [editorDialog, openEditorDialog, closeEditorDialog] = useDialogState<FolderChild>();
  const [imagePreviewDialog, openImagePreviewDialog, closeImagePreviewDialog] =
    useDialogState<FolderChild>();
  const [pdfPreviewDialog, openPdfPreviewDialog, closePdfPreviewDialog] =
    useDialogState<FolderChild>();
  const [audioPlayerDialog, openAudioPlayerDialog, closeAudioPlayerDialog] =
    useDialogState<FolderChild>();
  const [videoPlayerDialog, openVideoPlayerDialog, closeVideoPlayerDialog] =
    useDialogState<FolderChild>();
  const [createFolderDialogOpen, setCreateFolderDialogOpen] = useState(false);
  const [shareItem, setShareItem] = useState<FolderChild | null>(null);

  const [batchDeleteDialog, setBatchDeleteDialog] = useState<{
    open: boolean;
    items: FolderChild[];
  }>({ open: false, items: [] });

  const [batchMoveDialog, setBatchMoveDialog] = useState<{
    open: boolean;
    items: FolderChild[];
  }>({ open: false, items: [] });

  // ---------------------------------------------------------------------------
  // Handler callbacks
  // ---------------------------------------------------------------------------

  const handleNavigate = useCallback(
    (folderId: string) => {
      setSelectedIds(new Set());
      lastSelectedIdRef.current = null;
      navigateTo(folderId);
    },
    [navigateTo],
  );

  const handleSelect = useCallback(
    (itemId: string, event: { ctrlKey: boolean; shiftKey: boolean; metaKey: boolean }) => {
      const isCtrl = event.ctrlKey || event.metaKey;
      const isShift = event.shiftKey;

      if (isShift && lastSelectedIdRef.current) {
        const sortedChildren = [...children].sort((a, b) => {
          if (a.type === 'folder' && b.type !== 'folder') return -1;
          if (a.type !== 'folder' && b.type === 'folder') return 1;
          return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
        });
        const ids = sortedChildren.map((c) => c.id);
        const startIdx = ids.indexOf(lastSelectedIdRef.current);
        const endIdx = ids.indexOf(itemId);
        if (startIdx !== -1 && endIdx !== -1) {
          const rangeStart = Math.min(startIdx, endIdx);
          const rangeEnd = Math.max(startIdx, endIdx);
          const rangeIds = ids.slice(rangeStart, rangeEnd + 1);
          setSelectedIds((prev) => {
            const next = new Set(prev);
            for (const id of rangeIds) next.add(id);
            return next;
          });
        }
      } else if (isCtrl) {
        setSelectedIds((prev) => {
          const next = new Set(prev);
          if (next.has(itemId)) next.delete(itemId);
          else next.add(itemId);
          return next;
        });
        lastSelectedIdRef.current = itemId;
      } else {
        setSelectedIds(new Set([itemId]));
        lastSelectedIdRef.current = itemId;
      }
    },
    [children],
  );

  const handleSelectAll = useCallback(() => {
    if (selectedIds.size === children.length) {
      setSelectedIds(new Set());
      lastSelectedIdRef.current = null;
    } else {
      setSelectedIds(new Set(children.map((c) => c.id)));
    }
  }, [children, selectedIds.size]);

  const clearSelection = useCallback(() => {
    setSelectedIds(new Set());
    lastSelectedIdRef.current = null;
  }, []);

  const handleContextMenu = useCallback(
    (event: MouseEvent, item: FolderChild) => {
      if (!selectedIds.has(item.id)) {
        setSelectedIds(new Set([item.id]));
        lastSelectedIdRef.current = item.id;
      }
      contextMenu.show(event, item);
    },
    [contextMenu, selectedIds],
  );

  const handleDragStart = useCallback((_event: DragEvent, _item: FolderChild) => {
    // Drag data set by FileListItem
  }, []);

  const handleDropOnFolder = useCallback(
    async (
      items: Array<{ id: string; type: 'file' | 'folder' }>,
      sourceParentId: string,
      destFolderId: string,
    ) => {
      try {
        if (items.length === 1) {
          await moveItem(items[0].id, items[0].type, sourceParentId, destFolderId);
        } else {
          await moveItems(items, sourceParentId, destFolderId);
          clearSelection();
        }
      } catch (err) {
        logger.error('[FileBrowser] Move failed:', err);
      }
    },
    [moveItem, moveItems, clearSelection],
  );

  const handleDownload = useCallback(async () => {
    const item = contextMenu.item;
    if (!item || !isFilePointer(item)) return;
    const folderKey = currentFolder?.folderKey;
    if (!folderKey) return;
    try {
      await downloadFromIpns({
        fileMetaIpnsName: item.fileMetaIpnsName,
        folderKey,
        fileName: item.name,
      });
    } catch (err) {
      logger.error('[FileBrowser] Download failed:', err);
    }
  }, [contextMenu.item, downloadFromIpns, currentFolder?.folderKey]);

  const handleRenameClick = useCallback(() => {
    if (contextMenu.item) openRenameDialog(contextMenu.item);
  }, [contextMenu.item, openRenameDialog]);

  const handleDeleteClick = useCallback(() => {
    if (contextMenu.item) openConfirmDialog(contextMenu.item);
  }, [contextMenu.item, openConfirmDialog]);

  const handleMoveClick = useCallback(() => {
    if (contextMenu.item) openMoveDialog(contextMenu.item);
  }, [contextMenu.item, openMoveDialog]);

  const handleDetailsClick = useCallback(() => {
    if (contextMenu.item) openDetailsDialog(contextMenu.item);
  }, [contextMenu.item, openDetailsDialog]);

  const handleShareClick = useCallback(() => {
    if (contextMenu.item) setShareItem(contextMenu.item);
  }, [contextMenu.item]);

  const handleEditClick = useCallback(() => {
    if (contextMenu.item) openEditorDialog(contextMenu.item);
  }, [contextMenu.item, openEditorDialog]);

  const handlePreviewClick = useCallback(() => {
    const item = contextMenu.item;
    if (!item || !isFilePointer(item)) return;
    const name = item.name;
    if (isImageFile(name)) openImagePreviewDialog(item);
    else if (isPdfFile(name)) openPdfPreviewDialog(item);
    else if (isAudioFile(name)) openAudioPlayerDialog(item);
    else if (isVideoFile(name)) openVideoPlayerDialog(item);
  }, [
    contextMenu.item,
    openImagePreviewDialog,
    openPdfPreviewDialog,
    openAudioPlayerDialog,
    openVideoPlayerDialog,
  ]);

  const handleBatchDeleteClick = useCallback(() => {
    if (selectedItems.length === 0) return;
    setBatchDeleteDialog({ open: true, items: [...selectedItems] });
  }, [selectedItems]);

  const handleBatchMoveClick = useCallback(() => {
    if (selectedItems.length === 0) return;
    setBatchMoveDialog({ open: true, items: [...selectedItems] });
  }, [selectedItems]);

  const handleBatchDownload = useCallback(async () => {
    const files = selectedItems.filter(isFilePointer);
    if (files.length === 0) return;
    const folderKey = currentFolder?.folderKey;
    if (!folderKey) return;
    for (const file of files) {
      try {
        await downloadFromIpns({
          fileMetaIpnsName: file.fileMetaIpnsName,
          folderKey,
          fileName: file.name,
        });
      } catch (err) {
        logger.error('[FileBrowser] Batch download item failed:', err);
      }
    }
  }, [selectedItems, downloadFromIpns, currentFolder?.folderKey]);

  const handleBatchDeleteConfirm = useCallback(async () => {
    const items = batchDeleteDialog.items;
    if (items.length === 0) return;
    try {
      await deleteItems(
        items.map((i) => ({ id: i.id, type: i.type })),
        currentFolderId,
      );
      setBatchDeleteDialog({ open: false, items: [] });
      clearSelection();
    } catch (err) {
      logger.error('[FileBrowser] Batch delete failed:', err);
    }
  }, [batchDeleteDialog.items, deleteItems, currentFolderId, clearSelection]);

  const handleBatchMoveConfirm = useCallback(
    async (destinationFolderId: string) => {
      const items = batchMoveDialog.items;
      if (items.length === 0) return;
      try {
        await moveItems(
          items.map((i) => ({ id: i.id, type: i.type })),
          currentFolderId,
          destinationFolderId,
        );
        setBatchMoveDialog({ open: false, items: [] });
        clearSelection();
      } catch (err) {
        logger.error('[FileBrowser] Batch move failed:', err);
      }
    },
    [batchMoveDialog.items, moveItems, currentFolderId, clearSelection],
  );

  const closeBatchDeleteDialog = useCallback(() => {
    setBatchDeleteDialog({ open: false, items: [] });
  }, []);

  const closeBatchMoveDialog = useCallback(() => {
    setBatchMoveDialog({ open: false, items: [] });
  }, []);

  const handleRenameConfirm = useCallback(
    async (newName: string) => {
      const item = renameDialog.item;
      if (!item) return;
      try {
        await renameItem(item.id, item.type, newName, currentFolderId);
        closeRenameDialog();
      } catch (err) {
        logger.error('[FileBrowser] Rename failed:', err);
      }
    },
    [renameDialog.item, renameItem, currentFolderId, closeRenameDialog],
  );

  const handleDeleteConfirm = useCallback(async () => {
    const item = confirmDialog.item;
    if (!item) return;
    try {
      await deleteItem(item.id, item.type, currentFolderId);
      closeConfirmDialog();
    } catch (err) {
      logger.error('[FileBrowser] Delete failed:', err);
    }
  }, [confirmDialog.item, deleteItem, currentFolderId, closeConfirmDialog]);

  const handleMoveConfirm = useCallback(
    async (destinationFolderId: string) => {
      const item = moveDialog.item;
      if (!item) return;
      try {
        await moveItem(item.id, item.type, currentFolderId, destinationFolderId);
        closeMoveDialog();
      } catch (err) {
        logger.error('[FileBrowser] Move failed:', err);
      }
    },
    [moveDialog.item, moveItem, currentFolderId, closeMoveDialog],
  );

  const closeShareDialog = useCallback(() => {
    setShareItem(null);
  }, []);

  const openCreateFolderDialog = useCallback(() => {
    setCreateFolderDialogOpen(true);
  }, []);

  const closeCreateFolderDialog = useCallback(() => {
    setCreateFolderDialogOpen(false);
  }, []);

  const handleCreateFolderConfirm = useCallback(
    async (name: string) => {
      try {
        await createFolder(name, currentFolderId === 'root' ? null : currentFolderId);
      } catch (err) {
        logger.error('[FileBrowser] Create folder failed:', err);
      } finally {
        setCreateFolderDialogOpen(false);
      }
    },
    [createFolder, currentFolderId],
  );

  return {
    // Sync
    handleSync,
    // Drag
    isDraggingExternal,
    handleContentDragEnter,
    handleContentDragOver,
    handleContentDragLeave,
    handleContentDrop,
    handleExternalFileDrop,
    // Selection
    selectedIds,
    selectedItems,
    multiSelectActive,
    handleNavigate,
    handleSelect,
    handleSelectAll,
    clearSelection,
    // Context menu
    handleContextMenu,
    handleDragStart,
    handleDropOnFolder,
    // Item actions
    handleDownload,
    handleRenameClick,
    handleDeleteClick,
    handleMoveClick,
    handleDetailsClick,
    handleShareClick,
    handleEditClick,
    handlePreviewClick,
    // Batch actions
    handleBatchDeleteClick,
    handleBatchMoveClick,
    handleBatchDownload,
    handleBatchDeleteConfirm,
    handleBatchMoveConfirm,
    closeBatchDeleteDialog,
    closeBatchMoveDialog,
    // Dialog confirm/close
    handleRenameConfirm,
    handleDeleteConfirm,
    handleMoveConfirm,
    closeShareDialog,
    openCreateFolderDialog,
    closeCreateFolderDialog,
    handleCreateFolderConfirm,
    // Dialog states
    confirmDialog,
    closeConfirmDialog,
    renameDialog,
    closeRenameDialog,
    moveDialog,
    closeMoveDialog,
    detailsDialog,
    closeDetailsDialog,
    editorDialog,
    closeEditorDialog,
    imagePreviewDialog,
    closeImagePreviewDialog,
    pdfPreviewDialog,
    closePdfPreviewDialog,
    audioPlayerDialog,
    closeAudioPlayerDialog,
    videoPlayerDialog,
    closeVideoPlayerDialog,
    createFolderDialogOpen,
    shareItem,
    batchDeleteDialog,
    batchMoveDialog,
  };
}
