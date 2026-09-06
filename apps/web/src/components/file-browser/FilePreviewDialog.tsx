import { useFilePreview, type FilePreview } from '../../hooks/useFilePreview';
import type { ListingRow } from '../../vault/listing';
import { Modal } from '../ui/Modal';
import { MediaPlayer } from './MediaPlayer';

interface FilePreviewDialogProps {
  row: ListingRow;
  onClose: () => void;
  onDownload: () => void;
}

/** Shows one file's plaintext in the shapes the browser can render safely. */
export function FilePreviewDialog({ row, onClose, onDownload }: FilePreviewDialogProps) {
  const preview = useFilePreview(row.key, row.storedName, row.bytes);

  return (
    <Modal onClose={onClose} title={row.name} className="modal-backdrop--wide">
      <div className="preview-body" data-testid="file-preview-dialog">
        <PreviewContent preview={preview} name={row.name} />
      </div>
      <div className="dialog-actions">
        <button
          type="button"
          className="dialog-button"
          onClick={onDownload}
          data-testid="preview-download"
        >
          download
        </button>
        <button type="button" className="dialog-button dialog-button--primary" onClick={onClose}>
          close
        </button>
      </div>
    </Modal>
  );
}

function PreviewContent({ preview, name }: { preview: FilePreview; name: string }) {
  if (preview.status === 'loading') {
    return <p className="preview-status">{'// decrypting...'}</p>;
  }
  if (preview.status === 'error') {
    return (
      <p className="preview-status preview-status--error" role="alert">
        {preview.message}
      </p>
    );
  }
  if (preview.status === 'audio' || preview.status === 'video') {
    return <MediaPlayer url={preview.url} kind={preview.status} name={name} />;
  }
  if (preview.status === 'image') {
    return (
      <img className="preview-image" src={preview.url} alt={name} data-testid="preview-image" />
    );
  }
  if (preview.status === 'pdf') {
    // Chromium does not run its PDF viewer in a sandboxed frame.
    return (
      <iframe className="preview-pdf" src={preview.url} title={name} data-testid="preview-pdf" />
    );
  }
  return (
    <pre className="preview-text" data-testid="preview-text">
      {preview.text}
    </pre>
  );
}
