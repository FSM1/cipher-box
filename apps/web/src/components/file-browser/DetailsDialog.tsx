import { useState, useEffect, useCallback } from 'react';
import type { SealedChildRef, NodeContent } from '@cipherbox/core';
import type { ResolvedChild } from '@cipherbox/sdk';
import { Modal } from '../ui/Modal';
import { useFolderStore } from '../../stores/folder.store';
import { getSdkClient } from '../../lib/sdk-provider';
import '../../styles/details-dialog.css';
import { FileDetails } from './details/FileDetails';
import { FolderDetails } from './details/FolderDetails';

type DetailsDialogProps = {
  open: boolean;
  onClose: () => void;
  item: SealedChildRef | null;
  /**
   * The SDK-resolved display projection for `item`'s folder (SDK-READ-02) --
   * kind/size/modifiedAt pre-resolved, looked up by ipnsName (mirrors
   * FileList's `resolvedByIpnsName` pattern, 68.2-11). A miss (item not yet
   * present in the resolved listing) falls back to a folder-safe default
   * with unknown size/modifiedAt -- `SealedChildRef` no longer carries a
   * size/modifiedAt display mirror (D-08/68.2-12 revert).
   */
  resolvedChildren: ResolvedChild[];
  folderKey: Uint8Array | null;
  parentFolderId: string;
};

/**
 * Details dialog for file/folder metadata (node/v3).
 *
 * Shows technical information about the selected item. File metadata (size/mime/
 * versions) is resolved via `client.resolveFileMetadata` (68.2-11 SDK facade,
 * formerly the web-native file-metadata.service.ts); file-vs-folder
 * discrimination reads folderStore membership (the prior per-ipnsName kind
 * lookup cache is a 68.2 deletion target -- Plan 07 drops this dialog's
 * dependency on it).
 */
export function DetailsDialog({
  open,
  onClose,
  item,
  resolvedChildren,
  folderKey,
  parentFolderId,
}: DetailsDialogProps) {
  const [metadataCid, setMetadataCid] = useState<string | null>(null);
  const [metadataLoading, setMetadataLoading] = useState(false);
  const [fileMeta, setFileMeta] = useState<NodeContent | null>(null);
  const [fileMetaLoading, setFileMetaLoading] = useState(false);
  const [metadataRefresh, setMetadataRefresh] = useState(0);

  // 68.2-06 companion patch: FileDetails/FolderDetails render from
  // ResolvedChild (SDK-READ-02) rather than SealedChildRef (D-08 no-regression
  // render repoint). Look up the parent folder's SDK-resolved listing by
  // ipnsName (mirrors FileList's resolvedByIpnsName pattern, 68.2-11); a miss
  // (item not yet present in the resolved listing) falls back to a
  // folder-safe default with unknown size/modifiedAt -- `SealedChildRef` no
  // longer carries a size/modifiedAt display mirror (D-08/68.2-12 revert).
  const resolvedFromListing: ResolvedChild | undefined = item
    ? resolvedChildren.find((c) => c.ipnsName === item.ipnsName)
    : undefined;

  // Kind discriminator: prefer the SDK-authoritative `kind` from the resolved
  // parent listing (present for every child of the current folder, including
  // subfolders the user has not navigated into) and fall back to folderStore
  // membership only on a listing miss (the prior per-ipnsName kind cache was
  // dropped, D-07/68.2-07). Deriving solely from folderStore misclassified an
  // un-visited folder (absent from the store) as a file.
  const folderStoreEntry = useFolderStore((state) => {
    if (!item) return undefined;
    return Object.values(state.folders).find((f) => f.ipnsName === item.ipnsName);
  });
  const isFolderHeuristic = resolvedFromListing
    ? resolvedFromListing.kind === 'folder'
    : !!folderStoreEntry;

  const resolvedItem: ResolvedChild | null = item
    ? (resolvedFromListing ?? {
        ipnsName: item.ipnsName,
        name: item.name,
        kind: isFolderHeuristic ? 'folder' : 'file',
        size: undefined,
        // 0 sentinels for the still-loading/listing-miss fallback, matching the
        // existing modifiedAt: 0 precedent. When a real ResolvedChild is present
        // in the listing it flows through unchanged with its true
        // createdAt/modifiedAt; this literal is only the miss branch.
        createdAt: 0,
        modifiedAt: 0,
        sequence: 0,
      })
    : null;

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

    // Confirms the folder resolves via the SDK's gated facade (D-07;
    // client.getFolderMetadata delegates to the Plan-01 gated ensureFolderLoaded
    // path). The facade returns the folder's decoded Node, not the raw IPNS
    // resolve's CID -- that value isn't exposed at this layer, so this dialog's
    // "Metadata CID" technical-info row shows "unavailable" (FolderDetails'
    // existing null fallback) rather than depending on a raw IPNS resolve.
    getSdkClient()
      .getFolderMetadata(item.ipnsName)
      .then(() => {
        if (!cancelled) {
          setMetadataCid(null);
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

    getSdkClient()
      .resolveFileMetadata(item, folderKey)
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

  if (!item || !resolvedItem) return null;

  const title = isFolderHeuristic ? 'Folder Details' : 'File Details';

  return (
    <Modal open={open} onClose={onClose} title={title}>
      {!isFolderHeuristic ? (
        <FileDetails
          item={resolvedItem}
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
          item={resolvedItem}
          metadataCid={metadataCid}
          metadataLoading={metadataLoading}
          sequenceNumber={folderStoreEntry?.sequenceNumber ?? null}
          childCount={folderStoreEntry ? folderStoreEntry.children.length : null}
          folderKey={folderStoreEntry?.folderKey ?? null}
          ipnsPrivateKey={folderStoreEntry?.ipnsPrivateKey ?? null}
          readKeySealed={item.readKeySealed}
        />
      )}
    </Modal>
  );
}
