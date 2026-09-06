/**
 * Mock Delegated Routing Service for E2E Testing
 *
 * Records are stored in-memory and reset when the service restarts, so E2E
 * tests never pollute the public IPFS DHT. The store keeps the highest sequence
 * it has seen for a name: see the PUT route for the rule and why it exists.
 */

import Fastify, { type FastifyInstance, type FastifyServerOptions } from 'fastify';
import { readSequence } from './sequence.js';

const DEFAULT_LOGGER: FastifyServerOptions['logger'] = {
  level: process.env.LOG_LEVEL ?? 'info',
  transport:
    process.env.NODE_ENV !== 'production'
      ? { target: 'pino-pretty', options: { colorize: true } }
      : undefined,
};

export function buildServer(
  logger: FastifyServerOptions['logger'] = DEFAULT_LOGGER
): FastifyInstance {
  const fastify = Fastify({ logger });

  // Key: IPNS name (k51... or bafzaa...). The sequence is read once, at write
  // time, so the PUT rule never re-parses the record it already accepted.
  const ipnsRecords = new Map<string, { record: Buffer; sequence: bigint }>();

  // CORS headers for the browser-driven suites. PUT is advertised because this
  // store implements it: a record write carries a non-simple `Content-Type`, so
  // the browser preflights, and a policy naming only GET aborts the very publish
  // the route below serves.
  fastify.addHook('onRequest', async (request, reply) => {
    reply.header('Access-Control-Allow-Origin', '*');
    reply.header('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS');
    reply.header('Access-Control-Allow-Headers', 'Content-Type, Accept');
    if (request.method === 'OPTIONS') {
      return reply.status(204).send();
    }
  });

  fastify.get('/health', async () => {
    return { status: 'ok', records: ipnsRecords.size };
  });

  fastify.get<{ Params: { name: string } }>('/routing/v1/ipns/:name', async (request, reply) => {
    const { name } = request.params;

    const stored = ipnsRecords.get(name);
    if (!stored) {
      return reply.status(404).send({
        error: 'record not found',
        name,
      });
    }

    fastify.log.info({ name, size: stored.record.length }, 'Retrieved IPNS record');

    return reply
      .status(200)
      .header('Content-Type', 'application/vnd.ipfs.ipns-record')
      .send(stored.record);
  });

  // A real endpoint keeps the highest sequence it holds for a name, so a stale
  // re-PUT can never roll the name back. This store now does the same, and
  // answers a rollback 400 rather than accepting it. An equal sequence is the
  // keyless re-PUT keep-alive that the API republisher and the engine's hourly
  // pass both send, and a real endpoint acks it, so it stays a 200.
  //
  // The route is unauthenticated and reads the sequence from unsigned bytes, so
  // one bogus PUT raises the ceiling for a name until /forget/:name, /reset, or
  // a restart clears it. That is the price of the rule inside a hermetic store.
  fastify.put<{ Params: { name: string } }>('/routing/v1/ipns/:name', async (request, reply) => {
    const { name } = request.params;

    const body = request.body as Buffer;
    if (!body || body.length === 0) {
      return reply.status(400).send({
        error: 'empty request body',
      });
    }

    const sequence = readSequence(body);
    if (sequence === null) {
      fastify.log.info(
        { name, size: body.length },
        'Refused IPNS record with no readable sequence'
      );
      return reply.status(400).send({
        error: 'record sequence is unreadable',
        name,
      });
    }

    const stored = ipnsRecords.get(name);
    if (stored && sequence < stored.sequence) {
      const detail = {
        error: 'record sequence is older than the stored record',
        name,
        sequence: sequence.toString(),
        storedSequence: stored.sequence.toString(),
      };
      fastify.log.info(detail, 'Refused IPNS record that would roll the name back');
      return reply.status(400).send(detail);
    }

    ipnsRecords.set(name, { record: body, sequence });

    fastify.log.info(
      { name, size: body.length, sequence: sequence.toString(), totalRecords: ipnsRecords.size },
      'Stored IPNS record'
    );

    return reply.status(200).send({ ok: true });
  });

  fastify.addContentTypeParser(
    'application/vnd.ipfs.ipns-record',
    { parseAs: 'buffer' },
    async (_request: unknown, payload: Buffer) => payload
  );

  // Also accept application/octet-stream for compatibility
  fastify.addContentTypeParser(
    'application/octet-stream',
    { parseAs: 'buffer' },
    async (_request: unknown, payload: Buffer) => payload
  );

  // Test control, not routing API: forget ONE name, so a suite can starve a single
  // name of records while the rest of the store keeps answering.
  fastify.post<{ Params: { name: string } }>('/forget/:name', async (request) => {
    const { name } = request.params;
    const forgotten = ipnsRecords.delete(name);
    fastify.log.info({ name, forgotten }, 'Forgot IPNS record');
    return { ok: true, forgotten };
  });

  fastify.post('/reset', async () => {
    const count = ipnsRecords.size;
    ipnsRecords.clear();
    fastify.log.info({ clearedRecords: count }, 'Reset all IPNS records');
    return { ok: true, clearedRecords: count };
  });

  return fastify;
}
