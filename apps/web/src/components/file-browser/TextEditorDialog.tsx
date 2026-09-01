/**
 * Editing one text file in place. The load is the preview's — same allow-list,
 * same byte budget — and the save is the facade's streaming write, so the bytes
 * are framed and sealed by the engine and never by this layer.
 */

import { useEffect, useState } from 'react';
import { useFilePreview, type FilePreview } from '../../hooks/useFilePreview';
import { errorMessage } from '../../lib/errorMessage';
import { useEngine } from '../../providers/EngineProvider';
import type { ListingRow } from '../../vault/listing';
import { Modal } from '../ui/Modal';

/** One push per slice keeps peak memory off the file's size. */
const CHUNK_BYTES = 1024 * 1024;

interface TextEditorDialogProps {
  row: ListingRow;
  onClose: () => void;
}

export function TextEditorDialog({ row, onClose }: TextEditorDialogProps) {
  const client = useEngine();
  const loaded = useFilePreview(row.key, row.storedName, row.bytes);
  const [draft, setDraft] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  // Adopted once: a snapshot landing mid-edit re-reads the file, and a second
  // adoption would throw away what has been typed since.
  useEffect(() => {
    setDraft((current) => (current === null && loaded.status === 'text' ? loaded.text : current));
  }, [loaded]);

  const dirty = loaded.status === 'text' && draft !== null && draft !== loaded.text;

  const save = async (): Promise<void> => {
    if (client === null || draft === null) return;
    setSaving(true);
    setFailure(null);

    const facade = client.facade;
    const bytes = new TextEncoder().encode(draft);
    let handle: bigint | null = null;
    try {
      handle = await facade.beginWrite(
        { node: row.id, expectedVersion: row.contentCid ?? undefined },
        bytes.byteLength
      );
      for (let offset = 0; offset < bytes.byteLength; offset += CHUNK_BYTES) {
        await facade.pushChunk(handle, chunk(bytes, offset));
      }
      await facade.commitWrite(handle);
    } catch (error: unknown) {
      if (handle !== null) await facade.abortWrite(handle).catch(() => undefined);
      setFailure(errorMessage(error));
      setSaving(false);
      return;
    }
    onClose();
  };

  return (
    <Modal
      onClose={onClose}
      title={`edit ${row.name}`}
      className="modal-backdrop--wide"
      error={failure ?? refusal(loaded)}
      busy={saving}
    >
      <div className="dialog-content" data-testid="text-editor-dialog">
        {loaded.status === 'loading' && <p className="preview-status">{'// decrypting...'}</p>}
        {draft !== null && (
          <>
            <label className="dialog-label" htmlFor="text-editor-body">
              contents
            </label>
            <textarea
              id="text-editor-body"
              className="text-editor-field"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              disabled={saving}
              spellCheck={false}
              data-testid="text-editor-field"
            />
          </>
        )}
        <div className="dialog-actions">
          <button
            type="button"
            className="dialog-button"
            onClick={onClose}
            disabled={saving}
            data-testid="text-editor-cancel"
          >
            cancel
          </button>
          <button
            type="button"
            className="dialog-button dialog-button--primary"
            onClick={() => void save()}
            disabled={saving || !dirty}
            data-testid="text-editor-save"
          >
            {saving ? 'saving...' : 'save'}
          </button>
        </div>
      </div>
    </Modal>
  );
}

/** Why this file cannot be edited, or `null` while it still might be. */
function refusal(loaded: FilePreview): string | null {
  if (loaded.status === 'error') return loaded.message;
  return loaded.status === 'image' || loaded.status === 'pdf'
    ? 'no editor for this file type'
    : null;
}

/** A detachable copy: `pushChunk` transfers the buffer it is handed. */
function chunk(bytes: Uint8Array, offset: number): ArrayBuffer {
  return bytes.slice(offset, offset + CHUNK_BYTES).buffer as ArrayBuffer;
}
