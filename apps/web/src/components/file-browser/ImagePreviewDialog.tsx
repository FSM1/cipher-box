import type { FilePointer } from '@cipherbox/crypto';
import { Modal } from '../ui/Modal';
import { useFilePreview } from '../../hooks/useFilePreview';
import '../../styles/image-preview-dialog.css';

type ImagePreviewDialogProps = {
  open: boolean;
  onClose: () => void;
  item: FilePointer | null;
  /** Parent folder's decrypted AES-256 key (needed to decrypt file metadata) */
  folderKey: Uint8Array | null;
  /** Share ID when previewing from a shared folder — uses re-wrapped file keys */
  shareId?: string | null;
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
export function ImagePreviewDialog({
  open,
  onClose,
  item,
  folderKey,
  shareId,
}: ImagePreviewDialogProps) {
  const mimeType = item ? getMimeType(item.name) : 'application/octet-stream';

  const { loading, error, objectUrl, handleDownload } = useFilePreview({
    open,
    item,
    mimeType,
    folderKey,
    shareId,
  });

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
