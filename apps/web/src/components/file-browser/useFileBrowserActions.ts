/**
 * useFileBrowserActions -- Handler logic for FileBrowser.
 *
 * Contains all useCallback handlers, dialog state, selection state,
 * and drag state management.
 *
 * Phase 62: FolderChild → SealedChildRef. Behavioral stubs for item-type
 * discrimination (phase 63) and write-chain mutations (phase 65/68).
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
import type { SealedChildRef } from '@cipherbox/core';
import type { ResolvedChild } from '@cipherbox/sdk';
import { useDialogState } from '../../hooks/useDialogState';
import {
  isImageFile,
  isPdfFile,
  isAudioFile,
  isVideoFile,
  isFileRefResolved,
} from '../../utils/fileTypes';
import { useFolderStore } from '../../stores/folder.store';
import { useSyncStore } from '../../stores/sync.store';
import { isExternalFileDrag } from '../../hooks/useDropUpload';
import { getSdkClient } from '../../lib/sdk-provider';
import { downloadFileFromIpns, triggerBrowserDownload } from '../../services/download.service';
import { triggerSearchIndexRebuild } from '../../hooks/useSearch';
import { logger } from '../../lib/logger';
import { runWithFailureUx } from '../../hooks/useMutationFailureUx';

export type FileBrowserActionsParams = {
  currentFolderId: string;
  currentFolder: {
    children: SealedChildRef[];
    folderKey: Uint8Array;
  } | null;
  /**
   * SDK-resolved display listing for the current folder (68.2-15). Carries
   * per-child `kind` keyed by `ipnsName`; the identity-only `currentFolder.
   * children` (raw `SealedChildRef[]`) has no `.kind` after the 68.2-11
   * kind-cache removal, so file-vs-folder classification (download gating,
   * batch-download filtering) resolves against this instead.
   */
  resolvedChildren: ResolvedChild[];
  breadcrumbs: Array<{ id: string; name: string }>;
  navigateTo: (folderId: string) => void;
  navigateUp: () => void;
  createFolder: (name: string, parentFolderId: string | null) => Promise<{ ipnsName: string }>;
  renameItem: (
    itemId: string,
    itemType: 'file' | 'folder',
    newName: string,
    parentId: string
  ) => Promise<void>;
  moveItem: (
    itemId: string,
    itemType: 'file' | 'folder',
    sourceParentId: string,
    destParentId: string
  ) => Promise<void>;
  moveItems: (
    items: Array<{ id: string; type: 'file' | 'folder' }>,
    sourceParentId: string,
    destParentId: string
  ) => Promise<void>;
  deleteItem: (itemId: string, itemType: 'file' | 'folder', parentId: string) => Promise<void>;
  deleteItems: (
    items: Array<{ id: string; type: 'file' | 'folder' }>,
    parentId: string
  ) => Promise<void>;
  isOperating: boolean;
  isDownloading: boolean;
  downloadFromIpns: (params: {
    fileRef: SealedChildRef;
    folderKey: Uint8Array;
    fileName: string;
  }) => Promise<void>;
  handleFileDrop: (files: File[], folderId: string) => void;
  contextMenu: {
    visible: boolean;
    x: number;
    y: number;
    item: SealedChildRef | null;
    show: (event: MouseEvent, item: SealedChildRef) => void;
    hide: () => void;
  };
  rootIpnsName: string | null;
};

export function useFileBrowserActions(params: FileBrowserActionsParams) {
  const {
    currentFolderId,
    currentFolder,
    resolvedChildren,
    navigateTo,
    createFolder,
    renameItem,
    moveItem,
    moveItems,
    deleteItem,
    deleteItems,
    // downloadFromIpns: TODO(phase 65) - unused until file read-chain implemented
    handleFileDrop,
    contextMenu,
    rootIpnsName,
  } = params;

  const children = currentFolder?.children ?? [];

  // 68.2-15: kind lookup for identity-only refs (selection/context-menu items
  // are raw `SealedChildRef`s with no `.kind`) -- classify against the
  // SDK-resolved listing keyed by ipnsName (D-02, SDK-READ-02).
  const resolvedByIpnsName = useMemo(
    () => new Map(resolvedChildren.map((r) => [r.ipnsName, r])),
    [resolvedChildren]
  );

  // ---------------------------------------------------------------------------
  // Sync callback
  // ---------------------------------------------------------------------------

  const handleSync = useCallback(async () => {
    if (!rootIpnsName) return;

    const rootFolder = useFolderStore.getState().folders['root'];
    if (!rootFolder) return;

    try {
      // Background sync's resolve now routes through the SDK's own gated read
      // path (client.listFolder / client.ensureFolderLoaded, both backed by
      // ROT-07's durable anti-rollback floor) instead of the web's own
      // un-gated resolveIpnsRecord + fetchAndDecryptMetadata call (SC#1,
      // T-68.2-04). A gate rejection (SequenceRegressionError /
      // GenerationRegressionError) is routed through the same
      // runWithFailureUx classifier so it surfaces the D-05 toast instead of
      // failing silently, matching the prior web-side gate's behavior.
      //
      // 68.2-16: `{ forceResolve: true }` on both legs -- this callback fires
      // after a local write (post-upload refresh via UploadZone.onUploadComplete),
      // where the freshly-published record may still be within the SDK cache's
      // ipnsName+sequence window; without forcing, the refresh can return the
      // pre-write listing and the just-uploaded child never appears (D-03
      // deterministic freshness leg, mirroring refreshFolderListing/useSyncPolling).
      const client = getSdkClient();
      const resolved = await runWithFailureUx(() =>
        client.listFolder(rootIpnsName, { forceResolve: true })
      );
      // Route ensureFolderLoaded through the same D-05 classifier as listFolder
      // so a forced-resolve gate rejection (SequenceRegressionError /
      // GenerationRegressionError) surfaces the toast instead of only hitting
      // the catch-and-rethrow below.
      const state = await runWithFailureUx(() =>
        client.ensureFolderLoaded(rootIpnsName, { forceResolve: true })
      );

      // Plan 09 (68.2-09): the store's `children` field is now the SDK's
      // resolved `ResolvedChild[]` display projection (kind/size/modifiedAt
      // pre-resolved, SC#2) -- the store never independently resolves.
      // `rawChildren` is the same-session raw `SealedChildRef[]` mirror the
      // write path still needs (D-09).
      useFolderStore.getState().updateFolderChildren('root', resolved);
      if (state) {
        useFolderStore.getState().updateFolderRawChildren('root', state.children);
        useFolderStore.getState().updateFolderSequence('root', state.sequenceNumber);
      }
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
    [handleFileDrop, currentFolderId]
  );

  const handleExternalFileDrop = useCallback(
    (files: File[], targetFolderId: string) => {
      dragCounterRef.current = 0;
      setIsDraggingExternal(false);
      handleFileDrop(files, targetFolderId);
    },
    [handleFileDrop]
  );

  // ---------------------------------------------------------------------------
  // Selection state
  // ---------------------------------------------------------------------------

  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const lastSelectedIdRef = useRef<string | null>(null);

  // TODO(phase 63): SealedChildRef uses ipnsName as identifier (no .id)
  const childIds = useMemo(() => new Set(children.map((c) => c.ipnsName)), [children]);
  useEffect(() => {
    setSelectedIds((prev) => {
      if (prev.size === 0) return prev;
      const pruned = new Set([...prev].filter((id) => childIds.has(id)));
      if (pruned.size === prev.size) return prev;
      return pruned;
    });
  }, [childIds]);

  const selectedItems = useMemo(
    () => children.filter((c) => selectedIds.has(c.ipnsName)),
    [children, selectedIds]
  );
  const multiSelectActive = selectedIds.size > 0;

  // ---------------------------------------------------------------------------
  // Dialog states
  // ---------------------------------------------------------------------------

  const [confirmDialog, openConfirmDialog, closeConfirmDialog] = useDialogState<SealedChildRef>();
  const [renameDialog, openRenameDialog, closeRenameDialog] = useDialogState<SealedChildRef>();
  const [moveDialog, openMoveDialog, closeMoveDialog] = useDialogState<SealedChildRef>();
  const [detailsDialog, openDetailsDialog, closeDetailsDialog] = useDialogState<SealedChildRef>();
  const [editorDialog, openEditorDialog, closeEditorDialog] = useDialogState<SealedChildRef>();
  const [imagePreviewDialog, openImagePreviewDialog, closeImagePreviewDialog] =
    useDialogState<SealedChildRef>();
  const [pdfPreviewDialog, openPdfPreviewDialog, closePdfPreviewDialog] =
    useDialogState<SealedChildRef>();
  const [audioPlayerDialog, openAudioPlayerDialog, closeAudioPlayerDialog] =
    useDialogState<SealedChildRef>();
  const [videoPlayerDialog, openVideoPlayerDialog, closeVideoPlayerDialog] =
    useDialogState<SealedChildRef>();
  const [createFolderDialogOpen, setCreateFolderDialogOpen] = useState(false);
  const [shareItem, setShareItem] = useState<SealedChildRef | null>(null);

  const [batchDeleteDialog, setBatchDeleteDialog] = useState<{
    open: boolean;
    items: SealedChildRef[];
  }>({ open: false, items: [] });

  const [batchMoveDialog, setBatchMoveDialog] = useState<{
    open: boolean;
    items: SealedChildRef[];
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
    [navigateTo]
  );

  const handleSelect = useCallback(
    (itemId: string, event: { ctrlKey: boolean; shiftKey: boolean; metaKey: boolean }) => {
      const isCtrl = event.ctrlKey || event.metaKey;
      const isShift = event.shiftKey;

      if (isShift && lastSelectedIdRef.current) {
        // TODO(phase 63): SealedChildRef has no .type; sort alphabetically only
        const sortedChildren = [...children].sort((a, b) =>
          a.name.localeCompare(b.name, undefined, { sensitivity: 'base' })
        );
        const ids = sortedChildren.map((c) => c.ipnsName);
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
    [children]
  );

  const handleSelectAll = useCallback(() => {
    if (selectedIds.size === children.length) {
      setSelectedIds(new Set());
      lastSelectedIdRef.current = null;
    } else {
      // TODO(phase 63): SealedChildRef uses ipnsName as identifier
      setSelectedIds(new Set(children.map((c) => c.ipnsName)));
    }
  }, [children, selectedIds.size]);

  const clearSelection = useCallback(() => {
    setSelectedIds(new Set());
    lastSelectedIdRef.current = null;
  }, []);

  const handleContextMenu = useCallback(
    (event: MouseEvent, item: SealedChildRef) => {
      // TODO(phase 63): SealedChildRef uses ipnsName as identifier (no .id)
      if (!selectedIds.has(item.ipnsName)) {
        setSelectedIds(new Set([item.ipnsName]));
        lastSelectedIdRef.current = item.ipnsName;
      }
      contextMenu.show(event, item);
    },
    [contextMenu, selectedIds]
  );

  const handleDragStart = useCallback((_event: DragEvent, _item: SealedChildRef) => {
    // Drag data set by FileListItem
  }, []);

  const handleDropOnFolder = useCallback(
    async (
      items: Array<{ id: string; type: 'file' | 'folder' }>,
      sourceParentId: string,
      destFolderId: string
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
    [moveItem, moveItems, clearSelection]
  );

  const handleDownload = useCallback(async () => {
    const item = contextMenu.item;
    if (!item || !currentFolder) return;
    if (!isFileRefResolved(item, resolvedByIpnsName)) return; // No folder-archive download feature.
    try {
      const plaintext = await downloadFileFromIpns({
        fileRef: item,
        folderKey: currentFolder.folderKey,
      });
      triggerBrowserDownload(plaintext, item.name);
    } catch (err) {
      logger.error(`[FileBrowser] Download failed for ${item.name}:`, err);
    }
  }, [contextMenu.item, currentFolder, resolvedByIpnsName]);

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
    if (!item) return;
    // TODO(phase 63): SealedChildRef has no .type; open preview by name extension only
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
    if (!currentFolder || selectedItems.length === 0) return;
    for (const item of selectedItems.filter((it) => isFileRefResolved(it, resolvedByIpnsName))) {
      try {
        const plaintext = await downloadFileFromIpns({
          fileRef: item,
          folderKey: currentFolder.folderKey,
        });
        triggerBrowserDownload(plaintext, item.name);
      } catch (err) {
        logger.error(`[FileBrowser] Batch download failed for ${item.name}:`, err);
      }
    }
  }, [currentFolder, selectedItems, resolvedByIpnsName]);

  const handleBatchDeleteConfirm = useCallback(async () => {
    const items = batchDeleteDialog.items;
    if (items.length === 0) return;
    try {
      // TODO(phase 63): SealedChildRef uses ipnsName as id; stub type as 'folder'
      await deleteItems(
        items.map((i) => ({ id: i.ipnsName, type: 'folder' as const })), // phase-63 stub type
        currentFolderId
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
        // TODO(phase 63): SealedChildRef uses ipnsName as id; stub type as 'folder'
        await moveItems(
          items.map((i) => ({ id: i.ipnsName, type: 'folder' as const })), // phase-63 stub type
          currentFolderId,
          destinationFolderId
        );
        setBatchMoveDialog({ open: false, items: [] });
        clearSelection();
      } catch (err) {
        logger.error('[FileBrowser] Batch move failed:', err);
      }
    },
    [batchMoveDialog.items, moveItems, currentFolderId, clearSelection]
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
        // TODO(phase 63): SealedChildRef uses ipnsName as id; stub type as 'folder'
        await renameItem(item.ipnsName, 'folder', newName, currentFolderId); // phase-63 stub type
        closeRenameDialog();
      } catch (err) {
        logger.error('[FileBrowser] Rename failed:', err);
      }
    },
    [renameDialog.item, renameItem, currentFolderId, closeRenameDialog]
  );

  const handleDeleteConfirm = useCallback(async () => {
    const item = confirmDialog.item;
    if (!item) return;
    try {
      // TODO(phase 63): SealedChildRef uses ipnsName as id; stub type as 'folder'
      await deleteItem(item.ipnsName, 'folder', currentFolderId); // phase-63 stub type
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
        // TODO(phase 63): SealedChildRef uses ipnsName as id; stub type as 'folder'
        await moveItem(item.ipnsName, 'folder', currentFolderId, destinationFolderId); // phase-63 stub type
        closeMoveDialog();
      } catch (err) {
        logger.error('[FileBrowser] Move failed:', err);
      }
    },
    [moveDialog.item, moveItem, currentFolderId, closeMoveDialog]
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
    [createFolder, currentFolderId]
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
