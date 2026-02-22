import { useState, useEffect, useCallback, useRef } from 'react';
import type { FilePointer } from '@cipherbox/crypto';
import { Modal } from '../ui/Modal';
import { useAuthStore } from '../../stores/auth.store';
import { useFolder } from '../../hooks/useFolder';
import {
  downloadFile,
  downloadFileFromIpns,
  triggerBrowserDownload,
} from '../../services/download.service';
import { resolveFileMetadata } from '../../services/file-metadata.service';
import { fetchShareKeys } from '../../services/share.service';
import { encryptFile } from '../../services/file-crypto.service';
import { addToIpfs } from '../../lib/api/ipfs';
import '../../styles/text-editor-dialog.css';

type TextEditorDialogProps = {
  open: boolean;
  onClose: () => void;
  item: FilePointer | null;
  parentFolderId: string;
  /** Parent folder's decrypted AES-256 key (needed to decrypt file metadata) */
  folderKey: Uint8Array | null;
  /** When true, textarea is read-only and save is hidden */
  readOnly?: boolean;
  /** Share ID when viewing from a shared folder — uses re-wrapped file keys */
  shareId?: string | null;
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
}: TextEditorDialogProps) {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [content, setContent] = useState('');
  const [originalContent, setOriginalContent] = useState('');
  const [error, setError] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const { updateFile } = useFolder();

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

    if (!item.fileMetaIpnsName) {
      setLoading(false);
      setError('File metadata IPNS name not available (legacy v1 file?)');
      return;
    }

    let cancelled = false;
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
            resolveFileMetadata(item.fileMetaIpnsName, folderKey!),
            fetchShareKeys(shareId),
          ]);

          const fileKeyRecord = keys.find((k) => k.keyType === 'file' && k.itemId === item.id);
          if (!fileKeyRecord) {
            throw new Error('No re-wrapped file key available for this file');
          }

          plaintext = await downloadFile(
            {
              cid: fileMeta.cid,
              iv: fileMeta.fileIv,
              wrappedKey: fileKeyRecord.encryptedKey,
              originalName: item.name,
              encryptionMode: fileMeta.encryptionMode,
            },
            auth.vaultKeypair.privateKey
          );
        } else {
          // Owner path: use file key from metadata directly
          plaintext = await downloadFileFromIpns({
            fileMetaIpnsName: item.fileMetaIpnsName,
            folderKey: folderKey!,
            privateKey: auth.vaultKeypair.privateKey,
            fileName: item.name,
          });
        }

        if (cancelled) return;

        const text = new TextDecoder().decode(plaintext);
        setContent(text);
        setOriginalContent(text);
        setLoading(false);

        // Focus textarea after content loads (only in edit mode)
        if (!readOnly) {
          requestAnimationFrame(() => {
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
    };
  }, [open, item, folderKey, shareId, readOnly]);

  const handleSave = useCallback(async () => {
    if (!item || !isDirty) return;

    setSaving(true);
    setError(null);

    try {
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) {
        throw new Error('No keypair available - please log in again');
      }

      // 1. Encode content
      const encoded = new TextEncoder().encode(content);
      const file = new File([encoded], item.name);

      // 2. Encrypt with new key/IV
      const encrypted = await encryptFile(file, auth.vaultKeypair.publicKey);

      // 3. Upload to IPFS
      // Use .slice() to get a clean copy with its own ArrayBuffer,
      // avoiding sub-view issues if ciphertext is an offset view.
      const ciphertextBytes = encrypted.ciphertext.slice();
      const blob = new Blob([ciphertextBytes.buffer as ArrayBuffer]);
      const { cid } = await addToIpfs(blob);

      // 4. Update folder metadata
      await updateFile(parentFolderId, {
        fileId: item.id,
        newCid: cid,
        newFileKeyEncrypted: encrypted.wrappedKey,
        newFileIv: encrypted.iv,
        newSize: encrypted.originalSize,
      });

      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save file');
      setSaving(false);
    }
  }, [item, content, isDirty, parentFolderId, updateFile, onClose]);

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
