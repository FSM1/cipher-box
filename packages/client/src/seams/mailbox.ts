/**
 * `Mailbox` — the sealed-blob discovery transport over the API, via the `Http`
 * seam (blueprint/web-client.md seam table: "the engine's own API client over
 * the Http seam — nothing web-specific").
 *
 * A pure byte mover: it addresses the recipient and moves the opaque sealed
 * payload, and does no crypto or codec — the engine seals, unseals, and
 * authenticates every item (#39 D9). Response parsing (the pending-item list)
 * lands with the engine's mailbox pipeline slice; until then `poll` reports an
 * empty inbox, which is availability, never a trust decision — nothing on this
 * transport is load-bearing for safety.
 */

import { toHex } from './bytes.js';
import type { HttpSeam, MailboxItemData, MailboxSeam } from './types.js';

export class ApiMailbox implements MailboxSeam {
  constructor(
    private readonly http: HttpSeam,
    private readonly mailboxUrl: string
  ) {}

  async post(
    recipientPublicKey: Uint8Array,
    sealedPayload: Uint8Array,
    idempotencyKey: string
  ): Promise<void> {
    const response = await this.http.send({
      method: 'POST',
      url: this.mailboxUrl,
      headers: [
        ['content-type', 'application/octet-stream'],
        ['idempotency-key', idempotencyKey],
        ['x-recipient', toHex(recipientPublicKey)],
      ],
      body: sealedPayload,
    });
    if (response.status >= 300) {
      throw new Error(`mailbox post failed: ${response.status}`);
    }
  }

  poll(): Promise<MailboxItemData[]> {
    return Promise.resolve([]);
  }

  async ack(itemId: string): Promise<void> {
    const response = await this.http.send({
      method: 'DELETE',
      url: `${this.mailboxUrl}/${encodeURIComponent(itemId)}`,
      headers: [],
      body: null,
    });
    if (response.status >= 300 && response.status !== 404) {
      throw new Error(`mailbox ack failed: ${response.status}`);
    }
  }
}
