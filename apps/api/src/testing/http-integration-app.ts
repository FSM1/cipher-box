import { INestApplication, ModuleMetadata, Provider } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import { getDataSourceToken, getRepositoryToken } from '@nestjs/typeorm';
import { secp256k1 } from '@noble/curves/secp256k1';
import { DataSource } from 'typeorm';
import { configureApp } from '../app-setup';
import { User } from '../auth/entities/user.entity';
import { OpsModule } from '../ops/ops.module';
import { IntegrationDatabase } from './integration-db';

/** Default HS256 secret shared by the integration suites. */
export const INTEGRATION_JWT_SECRET = 'http-integration-secret';

export interface HttpIntegrationApp {
  app: INestApplication;
  http: ReturnType<INestApplication['getHttpServer']>;
  /** Close the app and restore the `JWT_SECRET` env the helper set on boot. */
  close: () => Promise<void>;
}

export interface HttpIntegrationOptions {
  /** A throwaway database from `createIntegrationDatabase` — the app reads/writes real Postgres. */
  db: IntegrationDatabase;
  /**
   * The HS256 secret the app signs/verifies access tokens with. The helper also
   * sets `process.env.JWT_SECRET` to this value so the account-keyed throttler
   * (which reads the env directly) trusts the tokens these tests mint. Defaults
   * to `INTEGRATION_JWT_SECRET`.
   */
  jwtSecret?: string;
  /** Entities exposed via `getRepositoryToken`, each backed by the real DataSource. */
  entities?: Parameters<typeof getRepositoryToken>[0][];
  controllers?: ModuleMetadata['controllers'];
  providers?: Provider[];
  /**
   * Import OpsModule — the global throttler + metrics. Default `true`. Set
   * `false` for suites that exercise a rate-limited surface past its own limit
   * (e.g. the auth flows fire far more than the auth surface's 10-request cap),
   * where the throttler is not under test and would otherwise 429 valid calls.
   */
  withOps?: boolean;
}

/**
 * Boot a real Nest HTTP app for the integration suite against a throwaway
 * Postgres: the production `configureApp` pipeline (ValidationPipe, cookie
 * parser, raw-body upload gate), the real global throttler + metrics interceptor
 * (OpsModule), a real JwtModule, and the real repositories/DataSource — no fake
 * persistence layer. Callers hand-list the controllers/providers of the module
 * under test exactly as its NestJS module wires them, so what is asserted over
 * HTTP is what ships. Advisory-lock serialization, refcount survivor checks, and
 * transaction isolation are exercised by genuine Postgres, closing the drift a
 * fake DataSource hides.
 */
export async function createHttpIntegrationApp(
  options: HttpIntegrationOptions
): Promise<HttpIntegrationApp> {
  const jwtSecret = options.jwtSecret ?? INTEGRATION_JWT_SECRET;
  const priorJwtSecret = process.env.JWT_SECRET;
  const restorePriorJwtSecret = () => {
    if (priorJwtSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = priorJwtSecret;
  };
  process.env.JWT_SECRET = jwtSecret;

  const repoProviders: Provider[] = (options.entities ?? []).map((entity) => ({
    provide: getRepositoryToken(entity),
    useValue: options.db.dataSource.getRepository(entity),
  }));

  let app: INestApplication | undefined;
  try {
    const moduleRef = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true }),
        ...(options.withOps === false ? [] : [OpsModule]),
        JwtModule.register({
          secret: jwtSecret,
          signOptions: { expiresIn: 900 },
        }),
      ],
      controllers: options.controllers ?? [],
      providers: [
        { provide: DataSource, useValue: options.db.dataSource },
        { provide: getDataSourceToken(), useValue: options.db.dataSource },
        ...repoProviders,
        ...(options.providers ?? []),
      ],
    }).compile();

    app = configureApp(moduleRef.createNestApplication());
    await app.init();
  } catch (err) {
    // Fail-closed: a boot failure must not leak the harness secret to the next
    // test file — the integration suite runs one sequential worker. Close any
    // partially-initialized app first (guarded so its own error can't mask the
    // original), then restore the env before rethrowing.
    if (app) {
      try {
        await app.close();
      } catch {
        /* keep the original boot error */
      }
    }
    restorePriorJwtSecret();
    throw err;
  }

  const bootedApp = app;
  const close = async () => {
    try {
      await bootedApp.close();
    } finally {
      restorePriorJwtSecret();
    }
  };

  return { app: bootedApp, http: bootedApp.getHttpServer(), close };
}

/** A throwaway compressed secp256k1 public key; the private key is zeroized. */
export function randomCompressedPublicKey(): string {
  const priv = secp256k1.utils.randomPrivateKey();
  try {
    return Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
  } finally {
    priv.fill(0);
  }
}

/**
 * Seed a real `users` row and mint a valid access token for it. The token is
 * signed with the JwtModule secret the app was booted with, so the guard and the
 * account-keyed throttler both accept it.
 */
export async function seedAccount(
  db: IntegrationDatabase,
  jwt: JwtService,
  overrides: Partial<User> = {}
): Promise<{ publicKey: string; token: string; userId: string }> {
  const publicKey = overrides.publicKey ?? randomCompressedPublicKey();
  const user = await db.dataSource
    .getRepository(User)
    .save({ byo: false, ...overrides, publicKey });
  const token = await jwt.signAsync({ sub: user.id, publicKey });
  return { publicKey, token, userId: user.id };
}
