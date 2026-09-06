import { buildServer } from './server.js';

const fastify = buildServer();

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
    fastify.log.info('  POST /forget/:name - Drop one record');
    fastify.log.info('  POST /reset - Clear all records');
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
