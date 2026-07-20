import { describe, expect, it } from 'vitest';
import { fakeConfig } from '../testing/fakes';
import { buildJwtOptions } from './auth.module';

describe('buildJwtOptions', () => {
  it('fails closed without JWT_SECRET in any deployed environment', () => {
    expect(() => buildJwtOptions(fakeConfig({ NODE_ENV: 'production' }).service)).toThrow(
      /JWT_SECRET is required/
    );
    expect(() => buildJwtOptions(fakeConfig({ NODE_ENV: 'staging' }).service)).toThrow(
      /JWT_SECRET is required/
    );
  });

  it('falls back to the dev secret only in development and test', () => {
    expect(buildJwtOptions(fakeConfig({ NODE_ENV: 'development' }).service).secret).toBe(
      'cipherbox-dev-jwt-secret'
    );
    expect(buildJwtOptions(fakeConfig({ NODE_ENV: 'test' }).service).secret).toBe(
      'cipherbox-dev-jwt-secret'
    );
  });

  it('uses the configured secret and access-token TTL', () => {
    const options = buildJwtOptions(
      fakeConfig({
        NODE_ENV: 'production',
        JWT_SECRET: 'configured-secret',
        ACCESS_TOKEN_TTL_SECONDS: '600',
      }).service
    );
    expect(options.secret).toBe('configured-secret');
    expect(options.signOptions.expiresIn).toBe(600);
  });
});
