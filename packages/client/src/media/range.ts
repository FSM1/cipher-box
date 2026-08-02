/**
 * Range resolution for the media byte pipe: a raw `Range` header plus the file
 * size to the response head and the plaintext window it carries.
 */

/** A half-open plaintext window `[offset, offset + length)`. */
export interface MediaWindow {
  readonly offset: number;
  readonly length: number;
}

/** The response head for a media request, with the window its body carries. */
export type MediaHead =
  | { status: 200 | 206; headers: Array<[string, string]>; window: MediaWindow }
  | { status: 416; headers: Array<[string, string]> };

const SUFFIX_FORM = /^-(\d+)$/;
const INTERVAL_FORM = /^(\d+)-(\d*)$/;

/**
 * A ticket URL is same-origin and top-level navigable, so a shared file's
 * attacker-chosen type would execute as the app itself. Only non-executable
 * media types survive; SVG scripts, so it is not one of them.
 */
export function safeMimeType(mimeType: string): string {
  const type = mimeType.split(';')[0].trim().toLowerCase();
  const playable =
    type.startsWith('audio/') || type.startsWith('video/') || type.startsWith('image/');
  return playable && !type.startsWith('image/svg') ? type : 'application/octet-stream';
}

/**
 * Belt to `safeMimeType`'s braces: no sniffing, and nothing the body names may
 * load or run. `no-store` keeps vault plaintext out of the HTTP cache — the pipe
 * hands the media element decrypted bytes, and nothing decrypted may outlive the
 * response.
 */
const hardening: Array<[string, string]> = [
  ['cache-control', 'no-store'],
  ['x-content-type-options', 'nosniff'],
  ['content-security-policy', "default-src 'none'; sandbox"],
];

function baseHeaders(mimeType: string, length: number): Array<[string, string]> {
  return [
    ['content-type', safeMimeType(mimeType)],
    ['content-length', String(length)],
    ['accept-ranges', 'bytes'],
    ...hardening,
  ];
}

function unsatisfiable(totalSize: number): MediaHead {
  return {
    status: 416,
    headers: [['content-range', `bytes */${totalSize}`], ...hardening],
  };
}

function whole(totalSize: number, mimeType: string): MediaHead {
  return {
    status: 200,
    headers: baseHeaders(mimeType, totalSize),
    window: { offset: 0, length: totalSize },
  };
}

/** Digit runs past `Number.MAX_SAFE_INTEGER` are not addressable — fail closed. */
function parseOffset(digits: string): number | null {
  const value = Number(digits);
  return Number.isSafeInteger(value) ? value : null;
}

/**
 * Resolves one media request. An absent, non-`bytes`, multi-range, or malformed
 * `Range` is answered with the whole file, which RFC 9110 permits and every
 * media element handles; only a syntactically valid range that addresses no
 * bytes of the file is a 416.
 */
export function resolveMediaRequest(
  rangeHeader: string | null,
  totalSize: number,
  mimeType: string
): MediaHead {
  if (rangeHeader === null || rangeHeader.trim() === '') return whole(totalSize, mimeType);

  const spec = rangeHeader.trim();
  if (!spec.toLowerCase().startsWith('bytes=')) return whole(totalSize, mimeType);
  const set = spec.slice('bytes='.length).trim();
  if (set.includes(',')) return whole(totalSize, mimeType);

  const suffix = SUFFIX_FORM.exec(set);
  if (suffix) {
    const wanted = parseOffset(suffix[1]);
    if (wanted === null) return unsatisfiable(totalSize);
    if (wanted === 0 || totalSize === 0) return unsatisfiable(totalSize);
    const offset = Math.max(0, totalSize - wanted);
    return partial(offset, totalSize - 1, totalSize, mimeType);
  }

  const interval = INTERVAL_FORM.exec(set);
  if (!interval) return whole(totalSize, mimeType);

  const offset = parseOffset(interval[1]);
  if (offset === null || offset >= totalSize) return unsatisfiable(totalSize);
  let last = totalSize - 1;
  if (interval[2] !== '') {
    const requestedLast = parseOffset(interval[2]);
    if (requestedLast === null) return unsatisfiable(totalSize);
    last = Math.min(requestedLast, last);
  }
  if (last < offset) return unsatisfiable(totalSize);
  return partial(offset, last, totalSize, mimeType);
}

function partial(offset: number, last: number, totalSize: number, mimeType: string): MediaHead {
  const length = last - offset + 1;
  return {
    status: 206,
    headers: [
      ...baseHeaders(mimeType, length),
      ['content-range', `bytes ${offset}-${last}/${totalSize}`],
    ],
    window: { offset, length },
  };
}
