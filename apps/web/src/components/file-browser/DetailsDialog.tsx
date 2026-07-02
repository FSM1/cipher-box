import { useState, useEffect, useCallback } from 'react';
import type { SealedChildRef, NodeContent } from '@cipherbox/core';
import { Modal } from '../ui/Modal';
import { useFolderStore } from '../../stores/folder.store';
import { resolveIpnsRecord } from '../../services/ipns.service';
import { resolveFileMetadata } from '../../services/file-metadata.service';
import '../../styles/details-dialog.css';
import { FileDetails } from './details/FileDetails';
import { FolderDetails } from './details/FolderDetails';

type DetailsDialogProps = {
  open: boolean;
  onClose: () => void;
  item: SealedChildRef | null;
  folderKey: Uint8Array | null;
  parentFolderId: string;
};

/**
 * Details dialog for file/folder metadata (node/v3).
 *
 * Shows technical information about the selected item. File metadata (size/mime/
 * versions) is resolved via `resolveFileMetadata` (68.1-04/68.1-06); the file-vs-folder
 * heuristic below (folderStore membership) stands until 68.1-14 wires `resolveKinds`
 * into folder-load render paths for definitive Node.kind discrimination.
 */
export function DetailsDialog({
  open,
  onClose,
  item,
  folderKey,
  parentFolderId,
}: DetailsDialogProps) {
  const [metadataCid, setMetadataCid] = useState<string | null>(null);
  const [metadataLoading, setMetadataLoading] = useState(false);
  const [fileMeta, setFileMeta] = useState<NodeContent | null>(null);
  const [fileMetaLoading, setFileMetaLoading] = useState(false);
  const [metadataRefresh, setMetadataRefresh] = useState(0);

  // Heuristic: if the folder store has a node for this ipnsName, treat as folder.
  // Replace with definitive Node.kind discrimination once 68.1-14 wires resolveKinds
  // into folder-load render paths (kind-cache.ts, D-02).
  const folderStoreEntry = useFolderStore((state) => {
    if (!item) return undefined;
    return Object.values(state.folders).find((f) => f.ipnsName === item.ipnsName);
  });
  const isFolderHeuristic = !!folderStoreEntry;

  // Resolve IPNS to get metadata CID (folder view only)
  useEffect(() => {
    if (!open || !item || !isFolderHeuristic) {
      if (!item || !isFolderHeuristic) {
        setMetadataCid(null);
        setMetadataLoading(false);
      }
      return;
    }

    if (!item.ipnsName) {
      setMetadataLoading(false);
      setMetadataCid(null);
      return;
    }

    let cancelled = false;
    setMetadataLoading(true);

    resolveIpnsRecord(item.ipnsName)
      .then((result) => {
        if (!cancelled) {
          setMetadataCid(result?.cid ?? null);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setMetadataCid(null);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setMetadataLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [open, item, isFolderHeuristic]);

  // Resolve per-file metadata (file view only)
  useEffect(() => {
    if (!open || !item || isFolderHeuristic || !folderKey) {
      setFileMeta(null);
      setFileMetaLoading(false);
      if (!open || !item) {
        setMetadataCid(null);
        setMetadataLoading(false);
      }
      return;
    }

    let cancelled = false;
    setFileMetaLoading(true);
    setMetadataLoading(true);

    resolveFileMetadata(item, folderKey)
      .then(({ metadata, metadataCid: cid }) => {
        if (!cancelled) {
          setFileMeta(metadata as unknown as NodeContent);
          setMetadataCid(cid);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setFileMeta(null);
          setMetadataCid(null);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setFileMetaLoading(false);
          setMetadataLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [open, item, folderKey, isFolderHeuristic, metadataRefresh]);

  const handleVersionAction = useCallback(() => {
    setMetadataRefresh((prev) => prev + 1);
  }, []);

  if (!item) return null;

  const title = isFolderHeuristic ? 'Folder Details' : 'File Details';

  return (
    <Modal open={open} onClose={onClose} title={title}>
      {!isFolderHeuristic ? (
        <FileDetails
          item={item}
          metadataCid={metadataCid}
          metadataLoading={metadataLoading}
          fileMeta={fileMeta}
          fileMetaLoading={fileMetaLoading}
          folderKey={folderKey}
          parentFolderId={parentFolderId}
          onVersionAction={handleVersionAction}
        />
      ) : (
        <FolderDetails
          item={item}
          metadataCid={metadataCid}
          metadataLoading={metadataLoading}
          sequenceNumber={folderStoreEntry?.sequenceNumber ?? null}
          childCount={folderStoreEntry ? folderStoreEntry.children.length : null}
        />
      )}
    </Modal>
  );
}
