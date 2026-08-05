/**
 * What a file can be shown as, decided by its name alone. The type is never
 * sniffed from the bytes and never comes off the wire: an allow-list keeps a
 * hostile name from talking the browser into rendering plaintext as an active
 * document (a blob URL inherits this origin).
 */

export type PreviewKind = 'image' | 'pdf' | 'text' | 'none';

/** Blobs the preview builds are typed from here, so nothing else can be. */
const PREVIEWABLE: Record<string, { kind: PreviewKind; mime: string }> = {
  png: { kind: 'image', mime: 'image/png' },
  jpg: { kind: 'image', mime: 'image/jpeg' },
  jpeg: { kind: 'image', mime: 'image/jpeg' },
  gif: { kind: 'image', mime: 'image/gif' },
  webp: { kind: 'image', mime: 'image/webp' },
  bmp: { kind: 'image', mime: 'image/bmp' },
  avif: { kind: 'image', mime: 'image/avif' },
  pdf: { kind: 'pdf', mime: 'application/pdf' },
  txt: { kind: 'text', mime: 'text/plain' },
  md: { kind: 'text', mime: 'text/plain' },
  json: { kind: 'text', mime: 'text/plain' },
  csv: { kind: 'text', mime: 'text/plain' },
  log: { kind: 'text', mime: 'text/plain' },
  ts: { kind: 'text', mime: 'text/plain' },
  js: { kind: 'text', mime: 'text/plain' },
  rs: { kind: 'text', mime: 'text/plain' },
  toml: { kind: 'text', mime: 'text/plain' },
  yaml: { kind: 'text', mime: 'text/plain' },
  yml: { kind: 'text', mime: 'text/plain' },
};

/** SVG is an image the browser will run scripts in, so it stays a download. */
export function previewKind(name: string): PreviewKind {
  return PREVIEWABLE[extension(name)]?.kind ?? 'none';
}

/** The blob type a preview may build for `name`; never a renderable default. */
export function previewMime(name: string): string {
  return PREVIEWABLE[extension(name)]?.mime ?? 'application/octet-stream';
}

function extension(name: string): string {
  const dot = name.lastIndexOf('.');
  return dot === -1 ? '' : name.slice(dot + 1).toLowerCase();
}
