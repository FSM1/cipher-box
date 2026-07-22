import { INestApplication, ModuleMetadata, Provider } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import { getDataSourceToken, getRepositoryToken } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { configureApp } from '../app-setup';
import { OpsModule } from '../ops/ops.module';
import { IntegrationDatabase } from './integration-db';

export interface HttpIntegrationApp {
  app: INestApplication;
  http: ReturnType<INestApplication['getHttpServer']>;
}

export interface HttpIntegrationOptions {
  /** A throwaway database from `createIntegrationDatabase` — the app reads/writes real Postgres. */
  db: IntegrationDatabase;
  /**
   * The HS256 secret the app signs/verifies access tokens with. Callers set
   * `process.env.JWT_SECRET` to the SAME value so the account-keyed throttler
   * (which reads the env directly) trusts the tokens these tests mint.
   */
  jwtSecret: string;
  /** Entities exposed via `getRepositoryToken`, each backed by the real DataSource. */
  entities?: Parameters<typeof getRepositoryToken>[0][];
  imports?: ModuleMetadata['imports'];
  controllers?: ModuleMetadata['controllers'];
  providers?: Provider[];
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
 * fake DataSource hides (#707, #725).
 */
export async function createHttpIntegrationApp(
  options: HttpIntegrationOptions
): Promise<HttpIntegrationApp> {
  const repoProviders: Provider[] = (options.entities ?? []).map((entity) => ({
    provide: getRepositoryToken(entity),
    useValue: options.db.dataSource.getRepository(entity),
  }));

  const moduleRef = await Test.createTestingModule({
    imports: [
      ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true }),
      OpsModule,
      JwtModule.register({ secret: options.jwtSecret, signOptions: { expiresIn: 900 } }),
      ...(options.imports ?? []),
    ],
    controllers: options.controllers ?? [],
    providers: [
      { provide: DataSource, useValue: options.db.dataSource },
      { provide: getDataSourceToken(), useValue: options.db.dataSource },
      ...repoProviders,
      ...(options.providers ?? []),
    ],
  }).compile();

  const app = configureApp(moduleRef.createNestApplication());
  await app.init();
  return { app, http: app.getHttpServer() };
}
