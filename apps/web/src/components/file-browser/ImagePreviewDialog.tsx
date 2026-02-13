import { useState, useEffect, useCallback } from 'react';
import type { FileEntry } from '@cipherbox/crypto';
import { Modal } from '../ui/Modal';
import { useAuthStore } from '../../stores/auth.store';
import { downloadFile } from '../../services/download.service';
import { triggerBrowserDownload } from '../../services/download.service';
import '../../styles/image-preview-dialog.css';

type ImagePreviewDialogProps = {
  open: boolean;
  onClose: () => void;
  item: FileEntry | null;
};

/** Map common image extensions to MIME types. */
const MIME_MAP: Record<string, string> = {
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.bmp': 'image/bmp',
  '.ico': 'image/x-icon',
  '.avif': 'image/avif',
};

function getMimeType(filename: string): string {
  const lower = filename.toLowerCase();
  const lastDot = lower.lastIndexOf('.');
  if (lastDot === -1) return 'application/octet-stream';
  const ext = lower.slice(lastDot);
  return MIME_MAP[ext] ?? 'application/octet-stream';
}

/**
 * Modal dialog for previewing image files in-browser.
 *
 * Downloads the encrypted file from IPFS, decrypts it, and displays
 * the image using an object URL. Includes a download button.
 */
export function ImagePreviewDialog({ open, onClose, item }: ImagePreviewDialogProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [objectUrl, setObjectUrl] = useState<string | null>(null);
  const [decryptedData, setDecryptedData] = useState<Uint8Array | null>(null);

  // Load and decrypt image when dialog opens
  useEffect(() => {
    if (!open || !item) {
      // Clean up object URL when closing
      if (objectUrl) {
        URL.revokeObjectURL(objectUrl);
      }
      setObjectUrl(null);
      setDecryptedData(null);
      setError(null);
      setLoading(false);
      return;
    }

    let cancelled = false;
    let url: string | null = null;
    setLoading(true);
    setError(null);

    (async () => {
      try {
        const auth = useAuthStore.getState();
        if (!auth.derivedKeypair) {
          throw new Error('No keypair available - please log in again');
        }

        const plaintext = await downloadFile(
          {
            cid: item.cid,
            iv: item.fileIv,
            wrappedKey: item.fileKeyEncrypted,
            originalName: item.name,
          },
          auth.derivedKeypair.privateKey
        );

        if (cancelled) return;

        const mime = getMimeType(item.name);
        const blob = new Blob([plaintext.buffer as ArrayBuffer], { type: mime });
        url = URL.createObjectURL(blob);

        setDecryptedData(plaintext);
        setObjectUrl(url);
        setLoading(false);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Failed to load image');
        setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
      if (url) {
        URL.revokeObjectURL(url);
      }
    };
  }, [open, item]);

  const handleDownload = useCallback(() => {
    if (!decryptedData || !item) return;
    triggerBrowserDownload(decryptedData, item.name, getMimeType(item.name));
  }, [decryptedData, item]);

  if (!item) return null;

  return (
    <Modal open={open} onClose={onClose} title={item.name} className="image-preview-modal">
      {loading ? (
        <div className="image-preview-loading">decrypting...</div>
      ) : error ? (
        <div className="image-preview-error">
          {'> '}
          {error}
        </div>
      ) : (
        <div className="image-preview-body">
          <div className="image-preview-container">
            {objectUrl && <img src={objectUrl} alt={item.name} className="image-preview-img" />}
          </div>
          <div className="image-preview-footer">
            <span className="image-preview-info">
              {'// '}
              {item.name}
            </span>
            <button
              type="button"
              className="dialog-button dialog-button--secondary"
              onClick={handleDownload}
            >
              --download
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}
