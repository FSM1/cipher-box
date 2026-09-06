import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from './server.js';

const NAME = 'k51qzi5uqu5dktest';

function varint(value: bigint): Buffer {
  const bytes: number[] = [];
  let rest = value;
  do {
    let byte = Number(rest & 0x7fn);
    rest >>= 7n;
    if (rest > 0n) {
      byte |= 0x80;
    }
    bytes.push(byte);
  } while (rest > 0n);
  return Buffer.from(bytes);
}

/** An IPNS entry carrying field 1 (`value`, bytes) and field 5 (`sequence`, varint). */
function record(sequence: bigint, value: string): Buffer {
  const valueBytes = Buffer.from(value, 'utf8');
  return Buffer.concat([
    Buffer.from([(1 << 3) | 2]),
    varint(BigInt(valueBytes.length)),
    valueBytes,
    Buffer.from([(5 << 3) | 0]),
    varint(sequence),
  ]);
}

describe('PUT /routing/v1/ipns/:name', () => {
  let app: FastifyInstance;

  beforeEach(() => {
    app = buildServer(false);
  });

  afterEach(async () => {
    await app.close();
  });

  const put = (body: Buffer) =>
    app.inject({
      method: 'PUT',
      url: `/routing/v1/ipns/${NAME}`,
      headers: { 'content-type': 'application/vnd.ipfs.ipns-record' },
      payload: body,
    });

  const stored = () => app.inject({ method: 'GET', url: `/routing/v1/ipns/${NAME}` });

  it('stores a record whose sequence is higher than the stored one', async () => {
    const second = record(7n, 'seven');

    expect((await put(record(4n, 'four'))).statusCode).toBe(200);
    expect((await put(second)).statusCode).toBe(200);

    const answer = await stored();
    expect(answer.statusCode).toBe(200);
    expect(answer.rawPayload).toEqual(second);
  });

  // The API republisher and the engine's hourly pass both re-PUT the record they
  // already hold, so an equal sequence is a keep-alive, not a rollback. The last
  // writer at a sequence wins, which is what the engine's own endpoint fake does
  // (crates/engine/src/testkit/fakes/record_store.rs keeps the held record only
  // when its sequence is strictly higher).
  it('accepts a record whose sequence equals the stored one, and the last writer wins', async () => {
    expect((await put(record(4n, 'four'))).statusCode).toBe(200);

    const sameSequence = record(4n, 'a different body at four');
    expect((await put(sameSequence)).statusCode).toBe(200);

    expect((await stored()).rawPayload).toEqual(sameSequence);
  });

  it('refuses a record whose sequence is lower than the stored one and keeps the stored record', async () => {
    const newer = record(7n, 'seven');
    expect((await put(newer)).statusCode).toBe(200);

    const refused = await put(record(4n, 'four'));
    expect(refused.statusCode).toBe(400);
    expect(refused.json()).toMatchObject({ sequence: '4', storedSequence: '7' });

    expect((await stored()).rawPayload).toEqual(newer);
  });

  it.each([
    ['no sequence field', Buffer.from([(1 << 3) | 2, 0x03, 0x61, 0x62, 0x63])],
    ['a truncated sequence varint', Buffer.from([(5 << 3) | 0, 0x80, 0x80])],
  ])('refuses a record with %s and keeps the stored record', async (_case, body) => {
    const newer = record(7n, 'seven');
    expect((await put(newer)).statusCode).toBe(200);

    const refused = await put(body);
    expect(refused.statusCode).toBe(400);
    expect(refused.json()).toMatchObject({ error: 'record sequence is unreadable' });

    expect((await stored()).rawPayload).toEqual(newer);
  });

  it('stores nothing when the first record for a name has no readable sequence', async () => {
    const refused = await put(Buffer.from([(1 << 3) | 2, 0x01, 0x61]));
    expect(refused.statusCode).toBe(400);

    expect((await stored()).statusCode).toBe(404);
  });
});
