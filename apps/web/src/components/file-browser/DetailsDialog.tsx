import { useState, useEffect, useCallback } from 'react';
import type { FolderChild, FilePointer, FileMetadata } from '@cipherbox/core';
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
  item: FolderChild | null;
  folderKey: Uint8Array | null;
  parentFolderId: string;
};

/**
 * Details dialog for file/folder metadata.
 *
 * Shows technical information about the selected item:
 * - Files: Content CID, metadata CID, encryption mode, IV, wrapped key, version history
 * - Folders: IPNS name, metadata CID, sequence number, wrapped keys
 *
 * Resolves the parent folder's IPNS record on open to get the live
 * metadata CID. Sensitive key material is displayed in redacted form.
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
  const [fileMeta, setFileMeta] = useState<FileMetadata | null>(null);
  const [fileMetaLoading, setFileMetaLoading] = useState(false);
  // Counter to force re-fetch after version restore/delete
  const [metadataRefresh, setMetadataRefresh] = useState(0);

  // For folders, also look up the folder node for sequence number and child count
  const folderNode = useFolderStore((state) =>
    item?.type === 'folder' ? state.folders[item.id] : undefined
  );

  // Resolve folder IPNS to get metadata CID (folders only)
  useEffect(() => {
    if (!open || !item || item.type !== 'folder') {
      if (!item || item.type !== 'file') {
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
  }, [open, item]);

  // Resolve per-file metadata and CID in a single IPNS call (files only)
  useEffect(() => {
    if (!open || !item || item.type !== 'file' || !folderKey) {
      setFileMeta(null);
      setFileMetaLoading(false);
      // Only reset shared metadataCid when dialog is closed, not when viewing a folder
      if (!open || !item) {
        setMetadataCid(null);
        setMetadataLoading(false);
      }
      return;
    }

    const fileItem = item as FilePointer;
    if (!fileItem.fileMetaIpnsName) {
      setFileMeta(null);
      setFileMetaLoading(false);
      setMetadataCid(null);
      setMetadataLoading(false);
      return;
    }

    let cancelled = false;
    setFileMetaLoading(true);
    setMetadataLoading(true);

    resolveFileMetadata(fileItem.fileMetaIpnsName, folderKey)
      .then(({ metadata, metadataCid: cid }) => {
        if (!cancelled) {
          setFileMeta(metadata);
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
  }, [open, item, folderKey, metadataRefresh]);

  // Callback to refresh metadata after version restore/delete
  const handleVersionAction = useCallback(() => {
    setMetadataRefresh((prev) => prev + 1);
  }, []);

  if (!item) return null;

  const title = item.type === 'folder' ? 'Folder Details' : 'File Details';

  return (
    <Modal open={open} onClose={onClose} title={title}>
      {item.type === 'file' ? (
        <FileDetails
          item={item as FilePointer}
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
          sequenceNumber={folderNode?.sequenceNumber ?? null}
          childCount={folderNode ? folderNode.children.length : null}
        />
      )}
    </Modal>
  );
}
