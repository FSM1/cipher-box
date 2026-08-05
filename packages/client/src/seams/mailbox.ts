/**
 * `Mailbox` — the sealed-blob discovery transport over the API mailbox routes
 * (blueprint/api.md "Mailbox"), via the `Http` seam.
 *
 * A pure byte mover: it addresses the recipient and moves the opaque sealed
 * payload, and does no crypto or codec — the engine seals, unseals, and
 * authenticates every item (#39 D9).
 */

import { fromBase64, toBase64, toHex } from './bytes.js';
import type { HttpSeam, MailboxItemData, MailboxSeam } from './types.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Mailbox routes are API-origin control-plane calls: they ride the HTTP-only
 * refresh cookie and carry the control-plane deadline.
 */
const API_REQUEST = { credentials: 'include', timeoutMs: 10_000 } as const;

export class ApiMailbox implements MailboxSeam {
  private readonly messagesUrl: string;

  constructor(
    private readonly http: HttpSeam,
    apiBaseUrl: string
  ) {
    this.messagesUrl = `${apiBaseUrl.replace(/\/+$/, '')}/mailbox/messages`;
  }

  async post(
    recipientPublicKey: Uint8Array,
    sealedPayload: Uint8Array,
    idempotencyKey: string
  ): Promise<void> {
    const body = JSON.stringify({
      recipientPublicKey: toHex(recipientPublicKey),
      blob: toBase64(sealedPayload),
      idempotencyKey,
    });
    const response = await this.http.send({
      method: 'POST',
      url: this.messagesUrl,
      headers: [['content-type', 'application/json']],
      body: encoder.encode(body),
      ...API_REQUEST,
    });
    if (response.status >= 300) {
      throw new Error(`mailbox post failed: ${response.status}`);
    }
  }

  async poll(): Promise<MailboxItemData[]> {
    const response = await this.http.send({
      method: 'GET',
      url: this.messagesUrl,
      headers: [],
      body: null,
      ...API_REQUEST,
    });
    if (response.status >= 300) {
      throw new Error(`mailbox poll failed: ${response.status}`);
    }
    // Fail-closed: an unreadable envelope is not an empty inbox.
    const wire = JSON.parse(decoder.decode(response.body)) as { messages?: unknown };
    if (!Array.isArray(wire.messages)) {
      throw new Error('mailbox poll returned no messages envelope');
    }
    return (wire.messages as unknown[]).map((message) => {
      const { id, blob } = (message ?? {}) as { id?: unknown; blob?: unknown };
      if (typeof id !== 'string' || typeof blob !== 'string') {
        throw new Error('mailbox poll returned a malformed message');
      }
      return { itemId: id, sealedPayload: fromBase64(blob) };
    });
  }

  async ack(itemId: string): Promise<void> {
    const response = await this.http.send({
      method: 'DELETE',
      url: `${this.messagesUrl}/${encodeURIComponent(itemId)}`,
      headers: [],
      body: null,
      ...API_REQUEST,
    });
    // The API's ack is idempotent — an unknown id answers 200 — so a 404 here
    // means the route is wrong, not that the item was already acked.
    if (response.status >= 300) {
      throw new Error(`mailbox ack failed: ${response.status}`);
    }
  }
}
