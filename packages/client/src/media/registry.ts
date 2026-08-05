/**
 * Ticket minting for the media byte pipe. A `/stream/<ticket>` URL is a bearer
 * capability to one file's plaintext, readable by any same-origin script that
 * can name it — so tickets are random and opaque, never derived from the node.
 */

import { STREAM_PATH_PREFIX, ticketFromUrl } from './protocol.js';

/** What a ticket resolves to: the content node plus what the head must declare. */
export interface MediaSource {
  readonly node: Uint8Array;
  readonly size: number;
  readonly mimeType: string;
}

export class StreamRegistry {
  private readonly sources = new Map<string, MediaSource>();

  constructor(
    /** The origin a stream URL must resolve to; tickets are same-origin capabilities. */
    private readonly origin: string,
    private readonly mintTicket: () => string = () => globalThis.crypto.randomUUID()
  ) {}

  /** Mints a ticket for `source` and returns the URL a media element requests. */
  register(source: MediaSource): string {
    const ticket = this.mintTicket();
    // A ticket names one file for its whole life — the broker pins an engine
    // stream per ticket, so a repeat would serve one file's plaintext under
    // another's head.
    if (this.sources.has(ticket)) throw new Error('a stream ticket must be minted once');
    this.sources.set(ticket, source);
    return `${STREAM_PATH_PREFIX}${ticket}`;
  }

  lookup(ticket: string): MediaSource | undefined {
    return this.sources.get(ticket);
  }

  /**
   * Takes any form of the URL `register` returned — including the absolute one a
   * media element reads back off `src`. Reports whether a ticket was dropped, so
   * a caller is never left believing plaintext is unreachable when it is not.
   */
  revoke(url: string): boolean {
    const ticket = ticketFromUrl(url, this.origin);
    return ticket !== null && this.sources.delete(ticket);
  }

  clear(): void {
    this.sources.clear();
  }
}
