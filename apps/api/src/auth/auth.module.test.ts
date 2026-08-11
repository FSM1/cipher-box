import { ConfigModule } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { describe, expect, it } from 'vitest';
import { RuntimeModule } from '../common/runtime.module';
import { fakeConfig } from '../testing/fakes';
import { AuthModule, buildJwtOptions } from './auth.module';
import { AuthMethod } from './entities/auth-method.entity';
import { IdentitySubject } from './entities/identity-subject.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { User } from './entities/user.entity';
import { GoogleOAuthService } from './services/google-oauth.service';

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

/**
 * Nest resolves constructor parameters from `design:paramtypes`, where an
 * interface-typed parameter emits no injectable token and refuses to resolve.
 * Every other suite hands these providers in ready-made, so only compiling the
 * module the way `AppModule` does catches that before a deployment boots.
 */
describe('AuthModule dependency graph', () => {
  it('instantiates every provider and controller Nest must resolve', async () => {
    const builder = Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true }),
        RuntimeModule,
        AuthModule,
      ],
    });
    for (const entity of [User, AuthMethod, RefreshToken, IdentitySubject]) {
      builder.overrideProvider(getRepositoryToken(entity)).useValue({});
    }

    const moduleRef = await builder.compile();
    await moduleRef.init();
    try {
      expect(moduleRef.get(GoogleOAuthService)).toBeInstanceOf(GoogleOAuthService);
    } finally {
      await moduleRef.close();
    }
  });
});
