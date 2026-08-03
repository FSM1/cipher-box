import type { IncomingMessage, ServerResponse } from 'node:http';

/**
 * In-memory mock of the API mailbox surface (blueprint/api.md "Mailbox"), for
 * the browser suite's `Mailbox` conformance run.
 *
 * It serves only the routes the real API serves and re-validates
 * `PostMessageDto` the way `apps/api/src/mailbox/dto/mailbox.dto.ts` does, so a
 * seam that drifts off the wire protocol fails here rather than in production.
 * Blobs stay opaque.
 *
 * The one deliberate substitution: the account whose inbox `poll`/`ack` read
 * comes from a path segment rather than a bearer JWT, since the browser suite
 * mints no tokens. Everything under `/mock-api/` that is not a served route is
 * a 404, so a route regression cannot fall through to the Vite HTML handler.
 */

const HEX_PUBLIC_KEY = /^(02|03)[0-9a-fA-F]{64}$|^04[0-9a-fA-F]{128}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{1,128}$/;

interface StoredMessage {
  id: string;
  receivedAt: string;
  blob: string;
}

const MESSAGES = /^\/mock-api\/([^/]+)\/mailbox\/messages(?:\/([^/?]+))?\/?(?:\?.*)?$/;

export function mockMailboxRequest(req: IncomingMessage, res: ServerResponse): boolean {
  const url = req.url ?? '';
  if (!url.startsWith('/mock-api/')) return false;

  const match = url.match(MESSAGES);
  if (!match) {
    send(res, 404, { error: 'no such mailbox route' });
    return true;
  }
  const account = decodeURIComponent(match[1]);
  const messageId = match[2] === undefined ? null : decodeURIComponent(match[2]);

  if (req.method === 'POST' && messageId === null) {
    void readBody(req).then(
      (body) => post(res, account, body),
      () => send(res, 400, { error: 'request aborted' })
    );
    return true;
  }
  if (req.method === 'GET' && messageId === null) {
    send(res, 200, { messages: inbox(account) });
    return true;
  }
  if (req.method === 'DELETE' && messageId !== null) {
    const pending = inbox(account);
    const index = pending.findIndex((message) => message.id === messageId);
    if (index >= 0) pending.splice(index, 1);
    send(res, 200, { success: true });
    return true;
  }

  send(res, 404, { error: 'no such mailbox route' });
  return true;
}

/** Pending messages per recipient publicKey, oldest first. */
const inboxes = new Map<string, StoredMessage[]>();
/** `sender|recipient|idempotencyKey` → the id its first post minted. */
const idempotency = new Map<string, string>();

function inbox(recipientPublicKey: string): StoredMessage[] {
  let pending = inboxes.get(recipientPublicKey);
  if (!pending) {
    pending = [];
    inboxes.set(recipientPublicKey, pending);
  }
  return pending;
}

function post(res: ServerResponse, sender: string, body: Buffer): void {
  let dto: { recipientPublicKey?: unknown; blob?: unknown; idempotencyKey?: unknown };
  try {
    dto = JSON.parse(body.toString('utf8')) as typeof dto;
  } catch {
    send(res, 400, { error: 'body must be JSON' });
    return;
  }

  const { recipientPublicKey, blob, idempotencyKey } = dto;
  if (typeof recipientPublicKey !== 'string' || !HEX_PUBLIC_KEY.test(recipientPublicKey)) {
    send(res, 400, { error: 'recipientPublicKey must be a hex secp256k1 public key' });
    return;
  }
  if (typeof blob !== 'string' || !BASE64.test(blob)) {
    send(res, 400, { error: 'blob must be base64' });
    return;
  }
  if (typeof idempotencyKey !== 'string' || !IDEMPOTENCY_KEY.test(idempotencyKey)) {
    send(res, 400, { error: 'idempotencyKey must be 1-128 url-safe characters' });
    return;
  }

  const scope = `${sender}|${recipientPublicKey}|${idempotencyKey}`;
  const seen = idempotency.get(scope);
  if (seen !== undefined) {
    send(res, 201, { id: seen });
    return;
  }

  const id = crypto.randomUUID();
  idempotency.set(scope, id);
  inbox(recipientPublicKey).push({ id, receivedAt: new Date().toISOString(), blob });
  send(res, 201, { id });
}

/** Collects a request body; an abort rejects rather than parking the promise. */
export function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function send(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(body));
}
