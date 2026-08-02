/** The tab-side server for the media byte pipe, answering over a brokered `MessagePort`. */

import { errorMessage } from '../errorMessage.js';
import {
  MEDIA_WINDOW_BYTES,
  type MediaRequest,
  type MediaResponse,
  type MessagePortLike,
} from './protocol.js';
import { resolveMediaRequest } from './range.js';
import type { StreamRegistry } from './registry.js';

/** The one engine capability the pipe needs; `EngineClient` satisfies it. */
export interface MediaReader {
  downloadRange(node: Uint8Array, offset: number, length: number): Promise<ArrayBuffer>;
}

/** An open response body: the unread remainder of a resolved window. */
interface Cursor {
  readonly node: Uint8Array;
  /** The mint-time window end, pulled in when a read proves the version is shorter. */
  end: number;
  offset: number;
  /** Reads chain onto this so two pulls can never straddle one cursor. */
  pump: Promise<void>;
}

export class MediaBroker {
  private readonly streams = new Map<number, Cursor>();
  private port: MessagePortLike | null = null;
  private listener: ((event: MessageEvent) => void) | null = null;

  constructor(
    private readonly registry: StreamRegistry,
    private readonly reader: MediaReader,
    private readonly windowBytes: number = MEDIA_WINDOW_BYTES
  ) {}

  /** The pipe carries one port; a fresh offer supersedes the port it replaces. */
  serve(port: MessagePortLike): void {
    this.close();
    const listener = (event: MessageEvent): void => {
      this.dispatch(port, event.data);
    };
    port.addEventListener('message', listener);
    port.start?.();
    this.port = port;
    this.listener = listener;
  }

  close(): void {
    if (this.port !== null && this.listener !== null) {
      this.port.removeEventListener('message', this.listener);
    }
    this.port = null;
    this.listener = null;
    this.streams.clear();
  }

  private dispatch(port: MessagePortLike, data: unknown): void {
    const request = asRequest(data);
    if (request === null) return;
    switch (request.type) {
      case 'cb:media:open':
        this.open(port, request.requestId, request.ticket, request.range);
        return;
      case 'cb:media:pull':
        this.pull(port, request.requestId);
        return;
      case 'cb:media:close':
        this.streams.delete(request.requestId);
        return;
    }
  }

  private open(
    port: MessagePortLike,
    requestId: number,
    ticket: string,
    range: string | null
  ): void {
    const postHead = (status: number, headers: Array<[string, string]>): void => {
      post(port, { type: 'cb:media:head', requestId, status, headers });
    };

    const source = this.registry.lookup(ticket);
    if (source === undefined) {
      postHead(404, []);
      return;
    }

    const head = resolveMediaRequest(range, source.size, source.mimeType);
    if (head.status === 416) {
      postHead(head.status, head.headers);
      return;
    }

    this.streams.set(requestId, {
      node: source.node,
      offset: head.window.offset,
      end: head.window.offset + head.window.length,
      pump: Promise.resolve(),
    });
    postHead(head.status, head.headers);
  }

  private pull(port: MessagePortLike, requestId: number): void {
    const cursor = this.streams.get(requestId);
    if (cursor === undefined) return;
    cursor.pump = cursor.pump.then(() => this.pump(port, requestId, cursor));
  }

  /**
   * Whether this cursor still owns the request. A close or a superseding open
   * can land at any await, and answering off a dropped cursor would post another
   * stream's plaintext under this request id.
   */
  private isCurrent(requestId: number, cursor: Cursor): boolean {
    return this.streams.get(requestId) === cursor;
  }

  private async pump(port: MessagePortLike, requestId: number, cursor: Cursor): Promise<void> {
    if (!this.isCurrent(requestId, cursor)) return;

    const remaining = cursor.end - cursor.offset;
    if (remaining <= 0) {
      this.streams.delete(requestId);
      post(port, { type: 'cb:media:end', requestId });
      return;
    }

    const offset = cursor.offset;
    const length = Math.min(this.windowBytes, remaining);
    try {
      const chunk = await this.reader.downloadRange(cursor.node, offset, length);
      if (!this.isCurrent(requestId, cursor)) return;
      cursor.offset = offset + chunk.byteLength;
      // A short read means the live version is smaller than the head promised;
      // ending here is a clean EOF, where under-delivering content-length is a
      // network error to the media element.
      if (chunk.byteLength < length) cursor.end = cursor.offset;
      const response: MediaResponse = { type: 'cb:media:chunk', requestId, chunk };
      port.postMessage(response, [chunk]);
    } catch (error) {
      if (!this.isCurrent(requestId, cursor)) return;
      this.streams.delete(requestId);
      post(port, { type: 'cb:media:error', requestId, message: errorMessage(error) });
    }
  }
}

function post(port: MessagePortLike, response: MediaResponse): void {
  port.postMessage(response);
}

/** A same-origin port is still untrusted input: anything off-shape is dropped. */
function asRequest(data: unknown): MediaRequest | null {
  if (typeof data !== 'object' || data === null) return null;
  const message = data as {
    type?: unknown;
    requestId?: unknown;
    ticket?: unknown;
    range?: unknown;
  };
  const requestId = message.requestId;
  if (typeof requestId !== 'number') return null;

  if (message.type === 'cb:media:open') {
    const { ticket, range } = message;
    if (typeof ticket !== 'string') return null;
    if (typeof range !== 'string' && range !== null) return null;
    return { type: 'cb:media:open', requestId, ticket, range };
  }
  if (message.type === 'cb:media:pull') return { type: 'cb:media:pull', requestId };
  if (message.type === 'cb:media:close') return { type: 'cb:media:close', requestId };
  return null;
}
