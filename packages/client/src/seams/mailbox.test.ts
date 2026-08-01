import { describe, expect, it } from 'vitest';

import { toBase64 } from './bytes.js';
import { ApiMailbox } from './mailbox.js';
import type { HttpRequestData, HttpResponseData, HttpSeam } from './types.js';

const BASE = 'https://api.example/';
const SEALED = new Uint8Array([0, 1, 2, 250, 255]);
const RECIPIENT = Uint8Array.from({ length: 33 }, (_, i) => (i === 0 ? 0x02 : i));

/** Records every request and replays a scripted response queue. */
class ScriptedHttp implements HttpSeam {
  readonly sent: HttpRequestData[] = [];

  constructor(private readonly responses: Array<Partial<HttpResponseData>>) {}

  send(request: HttpRequestData): Promise<HttpResponseData> {
    this.sent.push(request);
    const next = this.responses.shift();
    if (next === undefined) {
      return Promise.reject(new Error(`unscripted request: ${request.method} ${request.url}`));
    }
    return Promise.resolve({ status: 200, headers: [], body: new Uint8Array(), ...next });
  }
}

function json(status: number, body: unknown): Partial<HttpResponseData> {
  return { status, body: new TextEncoder().encode(JSON.stringify(body)) };
}

describe('ApiMailbox post', () => {
  it('sends the served route and the PostMessageDto body', async () => {
    const http = new ScriptedHttp([json(201, { id: 'mid' })]);
    await new ApiMailbox(http, BASE).post(RECIPIENT, SEALED, 'idem-1');

    const [request] = http.sent;
    expect(request.method).toBe('POST');
    expect(request.url).toBe('https://api.example/mailbox/messages');
    expect(request.headers).toEqual([['content-type', 'application/json']]);
    expect(JSON.parse(new TextDecoder().decode(request.body ?? new Uint8Array()))).toEqual({
      recipientPublicKey: '020102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
      blob: toBase64(SEALED),
      idempotencyKey: 'idem-1',
    });
  });

  it('rejects a non-2xx post', async () => {
    const http = new ScriptedHttp([json(404, {})]);
    await expect(new ApiMailbox(http, BASE).post(RECIPIENT, SEALED, 'k')).rejects.toThrow(
      /post failed: 404/
    );
  });
});

describe('ApiMailbox poll', () => {
  it('reads the messages envelope and decodes each sealed blob', async () => {
    const http = new ScriptedHttp([
      json(200, {
        messages: [
          { id: 'a', receivedAt: '2026-01-01T00:00:00.000Z', blob: toBase64(SEALED) },
          { id: 'b', receivedAt: '2026-01-02T00:00:00.000Z', blob: '' },
        ],
      }),
    ]);
    const items = await new ApiMailbox(http, BASE).poll();

    expect(http.sent[0].method).toBe('GET');
    expect(http.sent[0].url).toBe('https://api.example/mailbox/messages');
    expect(items).toEqual([
      { itemId: 'a', sealedPayload: SEALED },
      { itemId: 'b', sealedPayload: new Uint8Array() },
    ]);
  });

  it('reports an empty inbox only when the API says so', async () => {
    const http = new ScriptedHttp([json(200, { messages: [] })]);
    await expect(new ApiMailbox(http, BASE).poll()).resolves.toEqual([]);
  });

  it('rejects a non-2xx poll and an envelope with no messages array', async () => {
    await expect(new ApiMailbox(new ScriptedHttp([json(429, {})]), BASE).poll()).rejects.toThrow(
      /poll failed: 429/
    );
    await expect(new ApiMailbox(new ScriptedHttp([json(200, {})]), BASE).poll()).rejects.toThrow(
      /messages envelope/
    );
  });

  it('rejects a message that is not an id/blob pair', async () => {
    for (const message of [null, { id: 'a' }, { id: 7, blob: '' }]) {
      const http = new ScriptedHttp([json(200, { messages: [message] })]);
      await expect(new ApiMailbox(http, BASE).poll(), JSON.stringify(message)).rejects.toThrow(
        /malformed message/
      );
    }
  });
});

describe('ApiMailbox ack', () => {
  it('deletes on the served route', async () => {
    const http = new ScriptedHttp([json(200, { success: true })]);
    await new ApiMailbox(http, BASE).ack('mid 1/2');

    expect(http.sent[0].method).toBe('DELETE');
    expect(http.sent[0].url).toBe('https://api.example/mailbox/messages/mid%201%2F2');
  });

  it('rejects a 404 instead of recording a delete that never happened', async () => {
    const http = new ScriptedHttp([json(404, {})]);
    await expect(new ApiMailbox(http, BASE).ack('mid')).rejects.toThrow(/ack failed: 404/);
  });
});
