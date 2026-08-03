import { defineConfig, type Plugin } from 'vite';

import { mockMailboxRequest, readBody } from './mockMailbox.js';

/**
 * Serves the browser-suite harness and stands up an in-memory mock of the
 * network surfaces the seams touch: the `/routing/v1` delegated-routing
 * endpoint set (for `RecordTransport`), the API mailbox routes (for
 * `Mailbox`), and a couple of plain HTTP endpoints (for the `Http` seam
 * behavioral check). No crypto, no real network — the mock stores and returns
 * opaque bytes, exactly the shape the seam contracts exercise.
 */
function mockNetwork(): Plugin {
  const records = new Map<string, Buffer>();

  return {
    name: 'cipherbox-mock-network',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url ?? '';

        if (mockMailboxRequest(req, res)) return;

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
            void readBody(req).then(
              (record) => {
                records.set(key, record);
                res.statusCode = 200;
                res.end();
              },
              () => {
                res.statusCode = 400;
                res.end();
              }
            );
            return;
          }
        }

        if (url.startsWith('/mock-http/teapot')) {
          res.statusCode = 418;
          res.end('teapot');
          return;
        }

        if (url.startsWith('/mock-http/stream')) {
          // Chunked with no Content-Length: only the streaming cap can bound it.
          res.statusCode = 200;
          for (let sent = 0; sent < 64 * 1024; sent += 1024) {
            res.write(Buffer.alloc(1024, 7));
          }
          res.end();
          return;
        }

        if (url.startsWith('/mock-http/echo')) {
          void readBody(req).then(
            (body) => {
              res.statusCode = 200;
              res.setHeader('x-echo-method', req.method ?? '');
              res.end(body);
            },
            () => {
              res.statusCode = 400;
              res.end();
            }
          );
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
