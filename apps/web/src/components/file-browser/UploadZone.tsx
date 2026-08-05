import { useRef, useState, type DragEvent } from 'react';

interface UploadZoneProps {
  /** Handed the dropped or picked files; never called with an empty list. */
  onFiles: (files: File[]) => void;
  /** True while the engine still has an upload in hand. */
  busy: boolean;
}

/** Whether a drag carries files from outside the page rather than a page value. */
function carriesFiles(transfer: DataTransfer): boolean {
  return Array.from(transfer.types).includes('Files');
}

/** Where files enter the vault: a drop target that doubles as a file picker. */
export function UploadZone({ onFiles, busy }: UploadZoneProps) {
  const [dragging, setDragging] = useState(false);
  // `dragleave` fires for every child the pointer crosses.
  const depth = useRef(0);
  const picker = useRef<HTMLInputElement>(null);

  const enter = (event: DragEvent<HTMLDivElement>) => {
    if (!carriesFiles(event.dataTransfer)) return;
    depth.current += 1;
    setDragging(true);
  };

  const leave = () => {
    depth.current = Math.max(depth.current - 1, 0);
    if (depth.current === 0) setDragging(false);
  };

  const over = (event: DragEvent<HTMLDivElement>) => {
    if (!carriesFiles(event.dataTransfer)) return;
    // Without this the browser navigates to the dropped file instead.
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
  };

  const drop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    depth.current = 0;
    setDragging(false);
    const files = Array.from(event.dataTransfer.files);
    if (files.length > 0) onFiles(files);
  };

  return (
    <div
      className={`upload-zone${dragging ? ' upload-zone--dragging' : ''}`}
      data-testid="upload-zone"
      onDragEnter={enter}
      onDragOver={over}
      onDragLeave={leave}
      onDrop={drop}
    >
      <button
        type="button"
        className="upload-zone-button"
        data-testid="upload-zone-pick"
        onClick={() => picker.current?.click()}
      >
        <span className="upload-zone-icon" aria-hidden="true">
          [^]
        </span>
        <span className="upload-zone-text">
          {dragging ? '// DROP TO UPLOAD' : busy ? '// UPLOADING...' : '// UPLOAD FILES'}
        </span>
      </button>
      <input
        ref={picker}
        className="upload-zone-input"
        type="file"
        multiple
        aria-label="Choose files to upload"
        onChange={(event) => {
          const files = Array.from(event.target.files ?? []);
          // Cleared so picking the same file twice in a row still fires.
          event.target.value = '';
          if (files.length > 0) onFiles(files);
        }}
      />
    </div>
  );
}
