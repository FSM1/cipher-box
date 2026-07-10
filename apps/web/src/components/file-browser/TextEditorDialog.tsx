import { useState, useEffect, useCallback, useRef } from 'react';
import type { SealedChildRef } from '@cipherbox/core';
import { generateFileKey, generateIv, encryptAesGcm } from '@cipherbox/crypto';
import { Modal } from '../ui/Modal';
import { useAuthStore } from '../../stores/auth.store';
import { useFolderStore } from '../../stores/folder.store';
import { useVaultStore } from '../../stores/vault.store';
import { getRootFolderState } from '../../hooks/folder-helpers';
import { runWithFailureUx } from '../../hooks/useMutationFailureUx';
import { downloadFileFromIpns, triggerBrowserDownload } from '../../services/download.service';
import { shouldCreateVersion } from '../../lib/version-transforms';
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
  /**
   * Load handler for a DIRECT single-file share (68.1-32, WEB-03 writable-shares
   * 10.3) — recovers content via the node/v3 read chain (path []) instead of
   * `downloadFileFromIpns`. When supplied, the `!folderKey` early-return below
   * is skipped: a single-file share legitimately has a null `folderKey`.
   */
  onLoadSharedFileContent?: (item: SealedChildRef) => Promise<Uint8Array>;
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
  onLoadSharedFileContent,
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

    // A single-file share's root IS the file — folderKey is legitimately null
    // when the caller supplies onLoadSharedFileContent (68.1-32).
    if (!folderKey && !onLoadSharedFileContent) {
      setLoading(false);
      setError('Folder key not available');
      return;
    }

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

        if (onLoadSharedFileContent) {
          // DIRECT single-file share (68.1-32, WEB-03 writable-shares 10.3):
          // node/v3 read chain (path []) — no folderKey/readKeySealed dependency.
          plaintext = await onLoadSharedFileContent(item);
        } else if (shareId) {
          // Shared file path (node/v3 read chain, 68.1-29): the current shared
          // folder's readKey (folderKey prop) unseals the file's own readKey
          // from item.readKeySealed; the raw content fileKey lives inside the
          // file Node's read-body (NodeContent.fileKey). The previous
          // share_keys-based path here was dead — fetchShareKeys is
          // fail-closed empty since 68.1-20, so it always threw.
          plaintext = await downloadFileFromIpns({
            fileRef: item,
            folderKey: folderKey!,
          });
        } else if (hasSdkClient()) {
          // Owner path via SDK: resolves IPNS, decrypts metadata, downloads + decrypts content
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
  }, [open, item, folderKey, shareId, readOnly, onLoadSharedFileContent]);

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

        const client = getSdkClient();
        const { metadata: currentMetadata } = await client.resolveFileMetadata(item, folderKey);
        const createVersion = shouldCreateVersion(currentMetadata.versions, false);

        const encoded = new TextEncoder().encode(content);
        let newFileKey: Uint8Array | null = generateFileKey();
        const iv = generateIv();

        let prunedCids: string[] = [];
        try {
          const ciphertext = await encryptAesGcm(encoded, newFileKey, iv);
          const { cid } = await client.uploadBytes(ciphertext);

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
          client
            .unpin(prunedCid)
            .catch((err) => logger.warn('[TextEditor] Unpin pruned CID failed:', err));
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
