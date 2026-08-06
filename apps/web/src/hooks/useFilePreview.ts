/**
 * One file's plaintext, held only while its preview is on screen. An image is
 * pulled range by range through the Service Worker byte pipe, so nothing of it
 * is held in the tab; the shapes that must be decoded whole read through the
 * facade under a byte budget, and every URL is dropped on close.
 */

import { useEffect, useState } from 'react';
import { fromHex } from '@cipherbox/client';
import { errorMessage } from '../lib/errorMessage';
import { streamTicket } from '../lib/streamTicket';
import { useEngine, useMediaService } from '../providers/EngineProvider';
import { previewKind, previewMime, type PreviewKind } from '../vault/previewKind';

/** What a preview may pull into the tab: a memory ceiling, and a decode budget. */
const MAX_BUFFERED_BYTES = 32n * 1024n * 1024n;

const TOO_LARGE = 'too large to preview - download it instead';

export type FilePreview =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'image'; url: string }
  | { status: 'pdf'; url: string }
  | { status: 'text'; text: string };

/**
 * @param key the file's node id as lowercase hex, so the read keys on a value
 * @param size the engine's byte count, which caps the buffered read before it
 * decrypts a file too large to show; `null` while the projection is resolving
 */
export function useFilePreview(key: string, name: string, size: bigint | null): FilePreview {
  const client = useEngine();
  const media = useMediaService();
  const [preview, setPreview] = useState<FilePreview>({ status: 'loading' });

  useEffect(() => {
    if (client === null) {
      setPreview({ status: 'error', message: 'the engine is not ready yet' });
      return;
    }
    const kind = previewKind(name);
    if (kind === 'none') {
      setPreview({ status: 'error', message: 'no preview for this file type' });
      return;
    }
    // Reading first and measuring after would decrypt the whole file into the
    // tab before the budget could refuse it, so an unprojected size refuses now.
    if (size === null) {
      setPreview({ status: 'error', message: 'size not known yet - preview it again in a moment' });
      return;
    }

    const node = fromHex(key);
    // The pipe declares media types only, and an image is the one preview shape
    // that is one (packages/client/src/media/range.ts `safeMimeType`).
    if (kind === 'image') {
      const ticket = streamTicket(media, node, size, previewMime(name));
      if (ticket !== null) {
        setPreview({ status: 'image', url: ticket });
        return () => {
          media?.revokeStreamUrl(ticket);
        };
      }
    }

    if (size > MAX_BUFFERED_BYTES) {
      setPreview({ status: 'error', message: TOO_LARGE });
      return;
    }

    let url: string | null = null;
    let live = true;
    setPreview({ status: 'loading' });

    client.facade.download(node).then(
      (bytes) => {
        if (!live) return;
        // The projection can lag the file, so the bytes get the last word.
        if (BigInt(bytes.byteLength) > MAX_BUFFERED_BYTES) {
          setPreview({ status: 'error', message: TOO_LARGE });
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
  }, [key, name, size, client, media]);

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
