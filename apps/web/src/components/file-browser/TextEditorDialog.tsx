import { useState, useEffect, useCallback, useRef } from 'react';
import type { FileEntry } from '@cipherbox/crypto';
import { Modal } from '../ui/Modal';
import { useAuthStore } from '../../stores/auth.store';
import { useFolder } from '../../hooks/useFolder';
import { downloadFile } from '../../services/download.service';
import { encryptFile } from '../../services/file-crypto.service';
import { addToIpfs } from '../../lib/api/ipfs';
import '../../styles/text-editor-dialog.css';

type TextEditorDialogProps = {
  open: boolean;
  onClose: () => void;
  item: FileEntry | null;
  parentFolderId: string;
};

/**
 * Modal dialog for editing text files in-browser.
 *
 * Full crypto round-trip: download -> decrypt -> edit -> encrypt -> re-upload
 * -> update folder metadata -> unpin old CID.
 */
export function TextEditorDialog({ open, onClose, item, parentFolderId }: TextEditorDialogProps) {
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

    let cancelled = false;
    setLoading(true);
    setError(null);

    (async () => {
      try {
        const auth = useAuthStore.getState();
        if (!auth.vaultKeypair) {
          throw new Error('No keypair available - please log in again');
        }

        const plaintext = await downloadFile(
          {
            cid: item.cid,
            iv: item.fileIv,
            wrappedKey: item.fileKeyEncrypted,
            originalName: item.name,
          },
          auth.vaultKeypair.privateKey
        );

        if (cancelled) return;

        const text = new TextDecoder().decode(plaintext);
        setContent(text);
        setOriginalContent(text);
        setLoading(false);

        // Focus textarea after content loads
        requestAnimationFrame(() => {
          textareaRef.current?.focus();
        });
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Failed to load file');
        setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [open, item]);

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

  // Handle Ctrl/Cmd+S to save
  useEffect(() => {
    if (!open) return;

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
  }, [open, isDirty, saving, loading, handleSave]);

  if (!item) return null;

  const title = `Edit: ${item.name}`;
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
            onChange={(e) => setContent(e.target.value)}
            disabled={isDisabled}
            spellCheck={false}
            aria-label={`Content of ${item.name}`}
          />
          <div className={`text-editor-status${isDirty ? ' text-editor-status--modified' : ''}`}>
            <span>
              {'// '}
              {lineCount} {lineCount === 1 ? 'line' : 'lines'}
              {' | utf-8'}
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
          </div>
        </div>
      )}
    </Modal>
  );
}
