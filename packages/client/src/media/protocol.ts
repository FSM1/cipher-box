/**
 * The Service Worker byte-pipe wire (blueprint/web-client.md "Streaming media —
 * the SW is a dumb pipe"). Everything semantic — ticket lookup, Range
 * resolution, windowing — runs tab-side, so the worker holds no keys, no crypto
 * and no state beyond the port it currently has.
 */

/** The subset of `MessagePort` the pipe and the broker drive (injectable). */
export interface MessagePortLike {
  postMessage(message: unknown, transfer?: Transferable[]): void;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  start?(): void;
  close(): void;
}

/** Ticket URLs live under one path prefix so the fetch handler can be exact. */
export const STREAM_PATH_PREFIX = '/stream/';

/** The plaintext window read per pull: peak memory on both sides of the port is one window, never the file. */
export const MEDIA_WINDOW_BYTES = 1024 * 1024;

/** Service Worker → port. */
export type MediaRequest =
  /** Open a stream for `ticket`, resolving `range` (a raw `Range` header value). */
  | { type: 'cb:media:open'; requestId: number; ticket: string; range: string | null }
  /** Demand the next window; the stream's `ReadableStream.pull` drives this. */
  | { type: 'cb:media:pull'; requestId: number }
  /** The response body was cancelled or the stream is done with. */
  | { type: 'cb:media:close'; requestId: number };

/** Port → Service Worker. */
export type MediaResponse =
  /** The resolved status and headers; the body follows as `chunk`s until `end`. */
  | {
      type: 'cb:media:head';
      requestId: number;
      ok: boolean;
      status: number;
      headers: Array<[string, string]>;
    }
  /** One plaintext window, transferred. */
  | { type: 'cb:media:chunk'; requestId: number; chunk: ArrayBuffer }
  /** The window sequence is complete. */
  | { type: 'cb:media:end'; requestId: number }
  /** The read failed; the response body errors out. */
  | { type: 'cb:media:error'; requestId: number; message: string };

/** Tab → Service Worker, carrying the tab's end of a fresh `MessageChannel`. */
export type MediaPortOffer = { type: 'cb:media:port' };

/** Service Worker → every window client, when it holds no usable port. */
export type MediaPortRequest = { type: 'cb:media:needPort' };

export const MEDIA_PORT_OFFER = 'cb:media:port';
export const MEDIA_PORT_REQUEST = 'cb:media:needPort';

/** The ticket in a `/stream/<ticket>` path, or `null` for any other path. */
export function ticketFromPath(pathname: string): string | null {
  if (!pathname.startsWith(STREAM_PATH_PREFIX)) return null;
  const ticket = pathname.slice(STREAM_PATH_PREFIX.length);
  // A nested path is not a ticket: `/stream/a/b` must not resolve as `a/b`.
  return ticket.length > 0 && !ticket.includes('/') ? ticket : null;
}

/**
 * The ticket in any form of a stream URL the DOM hands back — absolute,
 * relative, query- or fragment-bearing. A URL resolving off `origin` names no
 * ticket of ours.
 */
export function ticketFromUrl(url: string, origin: string): string | null {
  let resolved: URL;
  try {
    resolved = new URL(url, origin);
  } catch {
    return null;
  }
  return resolved.origin === origin ? ticketFromPath(resolved.pathname) : null;
}
