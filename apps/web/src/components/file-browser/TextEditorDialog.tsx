import { useState, useEffect, useCallback, useRef } from 'react';
import type { SealedChildRef } from '@cipherbox/core';
import { generateFileKey, generateIv, encryptAesGcm } from '@cipherbox/crypto';
import { Modal } from '../ui/Modal';
import { useAuthStore } from '../../stores/auth.store';
import { useFolderStore } from '../../stores/folder.store';
import { useVaultStore } from '../../stores/vault.store';
import { getRootFolderState } from '../../hooks/folder-helpers';
import { runWithFailureUx } from '../../hooks/useMutationFailureUx';
import { downloadFile, triggerBrowserDownload } from '../../services/download.service';
import { resolveFileMetadata, shouldCreateVersion } from '../../services/file-metadata.service';
import { fetchShareKeys } from '../../services/share.service';
import { addToIpfs, unpinFromIpfs } from '../../lib/api/ipfs';
import { getSdkClient, hasSdkClient } from '../../lib/sdk-provider';
import { logger } from '../../lib/logger';
import '../../styles/text-editor-dialog.css';

type TextEditorDialogProps = {
  open: boolean;
  onClose: () => void;
  item: SealedChildRef | null;
  parentFolderId: string;
  /** Parent folder's decrypted AES-256 key (needed to decrypt file metadata) */
  folderKey: Uint8Array | null;
  /** When true, textarea is read-only and save is hidden */
  readOnly?: boolean;
  /** Share ID when viewing from a shared folder — uses re-wrapped file keys */
  shareId?: string | null;
  /** Save handler for shared files — updates file IPNS metadata via shared path */
  onSaveSharedFile?: (item: SealedChildRef, newContent: Uint8Array) => Promise<void>;
};

/**
 * Modal dialog for viewing/editing text files in-browser.
 *
 * In edit mode (default): full crypto round-trip with save.
 * In read-only mode: decrypt and display only (used for shared files).
 */
export function TextEditorDialog({
  open,
  onClose,
  item,
  parentFolderId,
  folderKey,
  readOnly,
  shareId,
  onSaveSharedFile,
}: TextEditorDialogProps) {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [content, setContent] = useState('');
  const [originalContent, setOriginalContent] = useState('');
  const [error, setError] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const isDirty = content !== originalContent;
  const lineCount = content.split('\n').length;

  // Load file content when dialog opens
  useEffect(() => {
    if (!open || !item) {
      setContent('');
      setOriginalContent('');
      setError(null);
      setLoading(false);
      setSaving(false);
      return;
    }

    if (!folderKey) {
      setLoading(false);
      setError('Folder key not available');
      return;
    }

    // TODO(phase 63): SealedChildRef.ipnsName is used where FilePointer.fileMetaIpnsName was
    if (!item.ipnsName) {
      setLoading(false);
      setError('File IPNS name not available');
      return;
    }

    let cancelled = false;
    let focusRaf: number | undefined;
    setLoading(true);
    setError(null);

    (async () => {
      try {
        const auth = useAuthStore.getState();
        if (!auth.vaultKeypair) {
          throw new Error('No keypair available - please log in again');
        }

        let plaintext: Uint8Array;

        if (shareId) {
          // Shared file path: use re-wrapped file key from share_keys
          const [{ metadata: fileMeta }, keys] = await Promise.all([
            resolveFileMetadata(item, folderKey!),
            fetchShareKeys(shareId),
          ]);

          // Exact match by itemId (folder share navigating to a specific file),
          // or fallback to first file key (standalone file share where id is shareId)
          const fileKeyRecord =
            keys.find((k) => k.keyType === 'file' && k.itemId === item.ipnsName) ||
            keys.find((k) => k.keyType === 'file');
          if (!fileKeyRecord) {
            throw new Error('File key not available — the folder owner may need to re-share');
          }
          const wrappedKey = fileKeyRecord.encryptedKey;

          plaintext = await downloadFile(
            {
              cid: fileMeta.cid,
              iv: fileMeta.fileIv,
              wrappedKey,
              originalName: item.name,
              encryptionMode: fileMeta.encryptionMode,
            },
            auth.vaultKeypair.privateKey
          );
        } else if (hasSdkClient()) {
          // Owner path via SDK: resolves IPNS, decrypts metadata, downloads + decrypts content
          // TODO(phase 63): SealedChildRef.ipnsName replaces FilePointer.fileMetaIpnsName
          const client = getSdkClient();
          plaintext = await client.downloadFromIpns(item, folderKey!);
        } else {
          throw new Error('SDK not initialized — please log in again');
        }

        if (cancelled) return;

        const text = new TextDecoder().decode(plaintext);
        setContent(text);
        setOriginalContent(text);
        setLoading(false);

        // Focus textarea after content loads (only in edit mode)
        if (!readOnly) {
          focusRaf = requestAnimationFrame(() => {
            textareaRef.current?.focus();
          });
        }
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Failed to load file');
        setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
      if (focusRaf !== undefined) cancelAnimationFrame(focusRaf);
    };
  }, [open, item, folderKey, shareId, readOnly]);

  const handleSave = useCallback(async () => {
    if (!item || !isDirty) return;

    setSaving(true);
    setError(null);

    try {
      if (shareId && onSaveSharedFile) {
        // Shared file path: delegate to shared navigation handler
        const encoded = new TextEncoder().encode(content);
        await onSaveSharedFile(item, encoded);
      } else {
        // Owner save path: encrypt the edited content fresh (no pre-existing
        // IPFS upload for in-place text edits), then publish via the file
        // write-chain (client.replaceFile, 68.1-09).
        if (!folderKey) {
          throw new Error('Folder key not available');
        }

        const folders = useFolderStore.getState().folders;
        const parentFolder =
          parentFolderId === 'root'
            ? getRootFolderState(useVaultStore.getState(), folders)
            : folders[parentFolderId];
        if (!parentFolder) {
          throw new Error('Parent folder not found or vault not initialized');
        }

        const { metadata: currentMetadata } = await resolveFileMetadata(item, folderKey);
        const createVersion = shouldCreateVersion(currentMetadata.versions, false);

        const encoded = new TextEncoder().encode(content);
        let newFileKey: Uint8Array | null = generateFileKey();
        const iv = generateIv();

        let prunedCids: string[] = [];
        try {
          const ciphertext = await encryptAesGcm(encoded, newFileKey, iv);
          const { cid } = await addToIpfs(new Blob([ciphertext as BlobPart]));

          const client = getSdkClient();
          // T-68.1-12-04: the write-chain walk lives only inside
          // CipherBoxClient (D-03). Do NOT zero it here — sdk-core
          // updateFileMetadata is its terminal owner (T-47-01).
          const fileIpnsPrivateKey = await client.resolveFileIpnsPrivateKey(
            parentFolder.ipnsName,
            item.ipnsName
          );

          ({ prunedCids } = await runWithFailureUx(() =>
            client.replaceFile(parentFolder.ipnsName, item.ipnsName, {
              fileIpnsPrivateKey,
              currentMetadata,
              updates: {
                cid,
                fileKey: newFileKey!,
                fileIv: iv,
                size: encoded.length,
                mimeType: currentMetadata.mimeType,
                encryptionMode: 'GCM',
              },
              createVersion,
            })
          ));
        } finally {
          newFileKey?.fill(0);
          newFileKey = null;
        }

        for (const prunedCid of prunedCids) {
          unpinFromIpfs(prunedCid).catch((err) =>
            logger.warn('[TextEditor] Unpin pruned CID failed:', err)
          );
        }
      }

      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save file');
      setSaving(false);
    }
  }, [item, content, isDirty, folderKey, parentFolderId, onClose, shareId, onSaveSharedFile]);

  // Handle Ctrl/Cmd+S to save (edit mode only)
  useEffect(() => {
    if (!open || readOnly) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 's') {
        e.preventDefault();
        if (isDirty && !saving && !loading) {
          handleSave();
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [open, readOnly, isDirty, saving, loading, handleSave]);

  const handleDownload = useCallback(() => {
    if (!item || !content) return;
    const encoded = new TextEncoder().encode(content);
    triggerBrowserDownload(encoded, item.name, 'text/plain');
  }, [item, content]);

  if (!item) return null;

  const title = readOnly ? `View: ${item.name}` : `Edit: ${item.name}`;
  const isDisabled = saving || loading;

  return (
    <Modal
      open={open}
      onClose={isDisabled ? undefined : onClose}
      title={title}
      className="text-editor-modal"
    >
      {loading ? (
        <div className="text-editor-loading">decrypting...</div>
      ) : (
        <div className="text-editor-body">
          <textarea
            ref={textareaRef}
            className="text-editor-textarea"
            value={content}
            onChange={readOnly ? undefined : (e) => setContent(e.target.value)}
            disabled={isDisabled}
            readOnly={readOnly}
            spellCheck={false}
            aria-label={`Content of ${item.name}`}
          />
          <div className={`text-editor-status${isDirty ? ' text-editor-status--modified' : ''}`}>
            <span>
              {'// '}
              {lineCount} {lineCount === 1 ? 'line' : 'lines'}
              {' | utf-8'}
              {readOnly ? ' | read-only' : ''}
              {isDirty ? ' | modified' : ''}
            </span>
          </div>
          {error && (
            <div className="text-editor-error">
              {'> '}
              {error}
            </div>
          )}
          <div className="text-editor-footer">
            {readOnly ? (
              <>
                <button
                  type="button"
                  className="dialog-button dialog-button--secondary"
                  onClick={handleDownload}
                >
                  --download
                </button>
                <button
                  type="button"
                  className="dialog-button dialog-button--primary"
                  onClick={onClose}
                >
                  close
                </button>
              </>
            ) : (
              <>
                <button
                  type="button"
                  className="dialog-button dialog-button--secondary"
                  onClick={onClose}
                  disabled={isDisabled}
                >
                  cancel
                </button>
                <button
                  type="button"
                  className="dialog-button dialog-button--primary"
                  onClick={handleSave}
                  disabled={isDisabled || !isDirty}
                >
                  {saving ? 'encrypting...' : '--save'}
                </button>
              </>
            )}
          </div>
        </div>
      )}
    </Modal>
  );
}
