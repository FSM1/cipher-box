/**
 * Mock Delegated Routing Service for E2E Testing
 *
 * Implements the IPFS delegated routing API for IPNS records:
 * - PUT /routing/v1/ipns/{name} - Store an IPNS record
 * - GET /routing/v1/ipns/{name} - Retrieve an IPNS record
 *
 * Records are stored in-memory and reset when the service restarts.
 * This allows E2E tests to run without polluting the public IPFS DHT
 * and avoids sequence number conflicts from repeated test runs.
 */

import Fastify from 'fastify';

const fastify = Fastify({
  logger: {
    level: process.env.LOG_LEVEL ?? 'info',
    transport:
      process.env.NODE_ENV !== 'production'
        ? { target: 'pino-pretty', options: { colorize: true } }
        : undefined,
  },
});

// In-memory storage for IPNS records
// Key: IPNS name (k51... or bafzaa...), Value: raw record bytes
const ipnsRecords = new Map<string, Buffer>();

// Health check endpoint
fastify.get('/health', async () => {
  return { status: 'ok', records: ipnsRecords.size };
});

// GET /routing/v1/ipns/{name} - Retrieve IPNS record
fastify.get<{ Params: { name: string } }>('/routing/v1/ipns/:name', async (request, reply) => {
  const { name } = request.params;

  const record = ipnsRecords.get(name);
  if (!record) {
    return reply.status(404).send({
      error: 'record not found',
      name,
    });
  }

  fastify.log.info({ name, size: record.length }, 'Retrieved IPNS record');

  return reply.status(200).header('Content-Type', 'application/vnd.ipfs.ipns-record').send(record);
});

// PUT /routing/v1/ipns/{name} - Store IPNS record
fastify.put<{ Params: { name: string } }>('/routing/v1/ipns/:name', async (request, reply) => {
  const { name } = request.params;

  // Get raw body as Buffer
  const body = request.body as Buffer;
  if (!body || body.length === 0) {
    return reply.status(400).send({
      error: 'empty request body',
    });
  }

  // Store the record (overwrites any existing record)
  // Note: We intentionally don't validate sequence numbers here.
  // This allows tests to reset state by simply restarting the service.
  ipnsRecords.set(name, body);

  fastify.log.info(
    { name, size: body.length, totalRecords: ipnsRecords.size },
    'Stored IPNS record'
  );

  return reply.status(200).send({ ok: true });
});

// Configure to accept raw binary bodies
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

// Reset endpoint for tests - clears all stored records
fastify.post('/reset', async () => {
  const count = ipnsRecords.size;
  ipnsRecords.clear();
  fastify.log.info({ clearedRecords: count }, 'Reset all IPNS records');
  return { ok: true, clearedRecords: count };
});

// Start server
const start = async () => {
  const host = process.env.HOST ?? '0.0.0.0';
  const port = parseInt(process.env.PORT ?? '3001', 10);

  try {
    await fastify.listen({ host, port });
    fastify.log.info(`Mock IPNS routing service listening on http://${host}:${port}`);
    fastify.log.info('Endpoints:');
    fastify.log.info('  GET  /health - Health check');
    fastify.log.info('  GET  /routing/v1/ipns/:name - Get IPNS record');
    fastify.log.info('  PUT  /routing/v1/ipns/:name - Store IPNS record');
    fastify.log.info('  POST /reset - Clear all records');
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
