import { INestApplication, ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, OpenAPIObject, SwaggerModule } from '@nestjs/swagger';
import cookieParser from 'cookie-parser';

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
    .build();
  return SwaggerModule.createDocument(app, config);
}
