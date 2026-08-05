/**
 * One file's plaintext, held only while its preview is on screen: the facade's
 * verified read, typed from the name allow-list, and revoked on close.
 */

import { useEffect, useState } from 'react';
import { fromHex } from '@cipherbox/client';
import { previewKind, previewMime, type PreviewKind } from '../components/file-browser/previewKind';
import { errorMessage } from '../lib/errorMessage';
import { useEngine } from '../providers/EngineProvider';

/** Past this a preview is a memory hazard, not a convenience. */
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024;

export type FilePreview =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'image'; url: string }
  | { status: 'pdf'; url: string }
  | { status: 'text'; text: string };

export interface PreviewTarget {
  /** The file's node id as lowercase hex, so the read keys on a value. */
  key: string;
  name: string;
}

/** `null` while nothing is being previewed. */
export function useFilePreview(target: PreviewTarget | null): FilePreview | null {
  const client = useEngine();
  const [preview, setPreview] = useState<FilePreview | null>(null);
  const key = target?.key ?? null;
  const name = target?.name ?? null;

  useEffect(() => {
    if (key === null || name === null || client === null) {
      setPreview(null);
      return;
    }
    const kind = previewKind(name);
    if (kind === 'none') {
      setPreview({ status: 'error', message: 'no preview for this file type' });
      return;
    }

    let url: string | null = null;
    let live = true;
    setPreview({ status: 'loading' });

    client.facade.download(fromHex(key)).then(
      (bytes) => {
        if (!live) return;
        if (bytes.byteLength > MAX_PREVIEW_BYTES) {
          setPreview({ status: 'error', message: 'too large to preview - download it instead' });
          return;
        }
        const rendered = render(kind, bytes, name);
        if (rendered.status === 'image' || rendered.status === 'pdf') url = rendered.url;
        setPreview(rendered);
      },
      (failure: unknown) => {
        if (live) setPreview({ status: 'error', message: errorMessage(failure) });
      }
    );

    return () => {
      live = false;
      if (url !== null) URL.revokeObjectURL(url);
    };
  }, [key, name, client]);

  return preview;
}

function render(kind: Exclude<PreviewKind, 'none'>, bytes: ArrayBuffer, name: string): FilePreview {
  if (kind === 'text') {
    try {
      return { status: 'text', text: new TextDecoder('utf-8', { fatal: true }).decode(bytes) };
    } catch {
      return { status: 'error', message: 'not valid UTF-8 text' };
    }
  }
  return {
    status: kind,
    url: URL.createObjectURL(new Blob([bytes], { type: previewMime(name) })),
  };
}
