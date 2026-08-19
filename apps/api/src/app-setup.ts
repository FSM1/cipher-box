import { INestApplication, ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, OpenAPIObject, SwaggerModule } from '@nestjs/swagger';
import cookieParser from 'cookie-parser';
import type { NextFunction, Request, Response } from 'express';
import { UPLOAD_TOO_LARGE, uploadTooLargeBody } from './content/upload-error-codes';
import { verifiedUnexpiredSubjectFromBearer } from './ops/account-throttler.guard';

/**
 * Absolute upload-size cap (coarse DoS guard); the quota gate is the fine one.
 * One request is one block, and Kubo's `block/put` refuses anything over 2 MiB —
 * a larger body would buffer in full only to fail at the pin store as a
 * retryable 503, so the transport cap refuses it here as a permanent 413.
 */
const DEFAULT_MAX_UPLOAD_BYTES = 2 * 1024 * 1024;

function maxUploadBytes(): number {
  const raw = process.env.MAX_UPLOAD_BYTES;
  const value = Number(raw);
  return raw !== undefined && Number.isInteger(value) && value > 0
    ? value
    : DEFAULT_MAX_UPLOAD_BYTES;
}

/**
 * Buffer an `application/octet-stream` body into `req.body` as a Buffer. Nest's
 * built-in json/urlencoded parsers skip octet-stream without consuming the
 * stream, so this runs as global middleware (before the async auth guard) to
 * capture the bytes deterministically — a stream read from inside the handler
 * would race the guard's `await`.
 *
 * The buffer is gated behind a VERIFIED, UNEXPIRED bearer signature: an
 * unauthenticated OR expired client is passed through unbuffered so the route's
 * `JwtAuthGuard` 401s it before it can force `maxBytes` of heap per connection
 * (a credential-less memory-exhaustion DoS). Expiry mirrors the guard's `exp`
 * check with the same secret, so a validly-signed-but-expired token cannot
 * buffer; only a genuine, rate-limited account does. The content-type match is
 * case-insensitive per RFC 9110. A body over the cap is answered with a 413 and
 * drained (never `req.destroy()`, which would reset the connection before the
 * 413 could flush).
 */
function rawUploadBody(maxBytes: number) {
  return (req: Request & { body?: unknown }, res: Response, next: NextFunction): void => {
    const contentType = (req.headers['content-type'] ?? '').toLowerCase();
    if (!contentType.includes('application/octet-stream')) {
      return next();
    }
    if (!verifiedUnexpiredSubjectFromBearer(req.headers as Record<string, unknown>)) {
      return next();
    }
    const chunks: Buffer[] = [];
    let total = 0;
    let aborted = false;
    req.on('data', (chunk: Buffer) => {
      if (aborted) return; // over the cap: drain the rest so the 413 can flush
      total += chunk.length;
      if (total > maxBytes) {
        aborted = true;
        res
          .status(413)
          .json(uploadTooLargeBody(UPLOAD_TOO_LARGE, `Upload exceeds ${maxBytes} bytes`));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!aborted) {
        req.body = Buffer.concat(chunks);
        next();
      }
    });
    req.on('error', (error) => {
      if (!aborted) next(error);
    });
  };
}

/**
 * Shared HTTP-pipeline configuration, applied identically by main.ts and by
 * the supertest apps in tests — what is asserted is what ships.
 */
export function configureApp(app: INestApplication): INestApplication {
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    })
  );
  app.use(cookieParser());
  app.use(rawUploadBody(maxUploadBytes()));
  return app;
}

/** CORS origin handling: exact origins plus wildcard patterns from env. */
export function corsOptionsFromEnv(rawOrigins: string | undefined) {
  const originEntries = rawOrigins
    ? rawOrigins.split(',').map((entry) => entry.trim())
    : ['http://localhost:5173', 'http://localhost:4173'];
  const exactOrigins = originEntries.filter((entry) => !entry.includes('*'));
  const wildcardPatterns = originEntries
    .filter((entry) => entry.includes('*'))
    .map(
      (entry) => new RegExp(`^${entry.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`)
    );

  return {
    origin: (
      origin: string | undefined,
      callback: (err: Error | null, allow?: boolean) => void
    ): void => {
      if (!origin) return callback(null, true);
      if (exactOrigins.includes(origin)) return callback(null, true);
      if (wildcardPatterns.some((pattern) => pattern.test(origin))) return callback(null, true);
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    },
    credentials: true,
  };
}

/**
 * The OpenAPI document, emitted from decorators. Committed at
 * apps/api/openapi.json as a docs artifact (blueprint/api.md, Contract and
 * clients) — documentation, never a build input; there are no generated
 * clients. The version is fixed: regeneration must be deterministic for the
 * CI freshness diff.
 */
export function buildOpenApiDocument(app: INestApplication): OpenAPIObject {
  const config = new DocumentBuilder()
    .setTitle('CipherBox API')
    .setDescription(
      'Zero-knowledge bookkeeping and accelerator service. The API never sees plaintext or unencrypted keys.'
    )
    .setVersion('2.0.0')
    .addBearerAuth()
    .addTag('Ops', 'Health and metrics')
    .addTag('Auth', 'Identity auth, SIWE secondary, refresh rotation')
    .addTag('Mailbox', 'Integrity-untrusted sealed-pointer transport: post, poll, ack')
    .addTag('Registry', 'Pin/name registry: batch register/retire, union liveness')
    .addTag('Account', 'Per-account quota and the BYO-IPFS toggle')
    .addTag('Content', 'Hosted ingress: quota-gated byte upload to CipherBox Kubo')
    .addTag('Recovery', 'Authenticated fetch of non-canonical cached record bytes by name')
    .addTag('Devices', 'The account device-identity-key registry that binds an approval')
    .addTag(
      'Device Approval',
      'Bulletin-board rendezvous relaying a sealed factor to a device that cannot yet reconstruct'
    )
    .build();
  return SwaggerModule.createDocument(app, config);
}
