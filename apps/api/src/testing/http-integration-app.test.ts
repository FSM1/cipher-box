import { Injectable, OnModuleInit } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { IntegrationDatabase } from './integration-db';
import { createHttpIntegrationApp } from './http-integration-app';

/** Forces `app.init()` to reject after the app is created, without a real DB. */
@Injectable()
class BootFailProvider implements OnModuleInit {
  onModuleInit(): void {
    throw new Error('boot failed');
  }
}

describe('createHttpIntegrationApp fail-closed teardown', () => {
  const SENTINEL = 'prior-secret-sentinel';
  let priorJwtSecret: string | undefined;

  beforeEach(() => {
    priorJwtSecret = process.env.JWT_SECRET;
  });

  afterEach(() => {
    if (priorJwtSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = priorJwtSecret;
  });

  it('restores JWT_SECRET when boot fails after the app is created', async () => {
    process.env.JWT_SECRET = SENTINEL;
    // No entities, so the DataSource stub is never dereferenced; the provider's
    // onModuleInit throws inside app.init(), after the partial app is assigned.
    const db = { dataSource: {} } as unknown as IntegrationDatabase;

    await expect(
      createHttpIntegrationApp({
        db,
        jwtSecret: 'boot-secret',
        withOps: false,
        providers: [BootFailProvider],
      })
    ).rejects.toThrow('boot failed');

    expect(process.env.JWT_SECRET).toBe(SENTINEL);
  });
});
