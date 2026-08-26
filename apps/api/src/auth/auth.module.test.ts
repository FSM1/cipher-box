import { Global, Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { getDataSourceToken, getRepositoryToken } from '@nestjs/typeorm';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RuntimeModule } from '../common/runtime.module';
import { fakeConfig } from '../testing/fakes';
import { AuthModule, buildJwtOptions } from './auth.module';
import { AuthMethod } from './entities/auth-method.entity';
import { AcceleratorToken } from './entities/accelerator-token.entity';
import { IdentitySubject } from './entities/identity-subject.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { User } from './entities/user.entity';
import { IdentityController } from './identity.controller';
import { EmailOtpService } from './services/email-otp.service';
import { GoogleOAuthService } from './services/google-oauth.service';
import { IdentityExchangeService } from './services/identity-exchange.service';
import { IdentitySubjectService } from './services/identity-subject.service';
import { IdentityTokenService } from './services/identity-token.service';
import { LoggingMailProvider, MailProvider } from './services/mail.provider';

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

/** Stands in for the root `TypeOrmModule.forRoot()` that `AppModule` supplies. */
@Global()
@Module({
  providers: [{ provide: getDataSourceToken(), useValue: {} }],
  exports: [getDataSourceToken()],
})
class StubDataSourceModule {}

/**
 * Nest resolves constructor parameters from `design:paramtypes`, where an
 * interface-typed parameter emits no injectable token and refuses to resolve.
 * Every other suite hands these providers in ready-made, so only compiling the
 * module the way `AppModule` does catches that before a deployment boots.
 */
describe('AuthModule dependency graph', () => {
  // Named rather than inherited: both the mail provider and the identity
  // signing key are allowlisted by NODE_ENV, so an ambient one decides which
  // graph this compiles.
  beforeEach(() => vi.stubEnv('NODE_ENV', 'test'));
  afterEach(() => vi.unstubAllEnvs());

  it('instantiates every provider and controller Nest must resolve', async () => {
    const builder = Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true }),
        RuntimeModule,
        StubDataSourceModule,
        AuthModule,
      ],
    });
    for (const entity of [User, AuthMethod, RefreshToken, AcceleratorToken, IdentitySubject]) {
      builder.overrideProvider(getRepositoryToken(entity)).useValue({});
    }

    const moduleRef = await builder.compile();
    await moduleRef.init();
    try {
      expect(moduleRef.get(IdentityController)).toBeInstanceOf(IdentityController);
      expect(moduleRef.get(GoogleOAuthService)).toBeInstanceOf(GoogleOAuthService);
      expect(moduleRef.get(EmailOtpService)).toBeInstanceOf(EmailOtpService);
      expect(moduleRef.get(IdentityExchangeService)).toBeInstanceOf(IdentityExchangeService);
      expect(moduleRef.get(IdentitySubjectService)).toBeInstanceOf(IdentitySubjectService);
      expect(moduleRef.get(IdentityTokenService)).toBeInstanceOf(IdentityTokenService);
      // The factory-built provider resolves too, and lands on the test-only
      // fallback the named NODE_ENV allowlists.
      expect(moduleRef.get(MailProvider)).toBeInstanceOf(LoggingMailProvider);
    } finally {
      await moduleRef.close();
    }
  });
});
