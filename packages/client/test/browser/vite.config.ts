import { defineConfig, type Plugin } from 'vite';

/**
 * Serves the browser-suite harness and stands up an in-memory mock of the two
 * network surfaces the seams touch: the `/routing/v1` delegated-routing
 * endpoint set (for `RecordTransport`) and a couple of plain HTTP endpoints
 * (for the `Http` seam behavioral check). No crypto, no real network — the
 * mock stores and returns opaque bytes, exactly the shape the seam contracts
 * exercise.
 */
function mockNetwork(): Plugin {
  const records = new Map<string, Buffer>();

  return {
    name: 'cipherbox-mock-network',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url ?? '';

        const routing = url.match(/\/routing\/v1\/ipns\/([^/?]+)/);
        if (routing) {
          const key = decodeURIComponent(routing[1]);
          if (req.method === 'GET') {
            const record = records.get(key);
            if (!record) {
              res.statusCode = 404;
              res.end();
              return;
            }
            res.statusCode = 200;
            res.setHeader('content-type', 'application/vnd.ipfs.ipns-record');
            res.end(record);
            return;
          }
          if (req.method === 'PUT') {
            const chunks: Buffer[] = [];
            req.on('data', (chunk: Buffer) => chunks.push(chunk));
            req.on('end', () => {
              records.set(key, Buffer.concat(chunks));
              res.statusCode = 200;
              res.end();
            });
            return;
          }
        }

        if (url.startsWith('/mock-http/teapot')) {
          res.statusCode = 418;
          res.end('teapot');
          return;
        }

        if (url.startsWith('/mock-http/echo')) {
          const chunks: Buffer[] = [];
          req.on('data', (chunk: Buffer) => chunks.push(chunk));
          req.on('end', () => {
            res.statusCode = 200;
            res.setHeader('x-echo-method', req.method ?? '');
            res.end(Buffer.concat(chunks));
          });
          return;
        }

        next();
      });
    },
  };
}

export default defineConfig({
  root: import.meta.dirname,
  plugins: [mockNetwork()],
  server: {
    port: 5178,
    strictPort: true,
  },
});
