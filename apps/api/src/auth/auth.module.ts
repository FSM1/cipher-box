import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { OpsModule } from '../ops/ops.module';
import { AuthMetricsInterceptor } from './auth-metrics.interceptor';
import { AuthController } from './auth.controller';
import { AuthMethod } from './entities/auth-method.entity';
import { GatewayToken } from './entities/gateway-token.entity';
import { IdentitySubject } from './entities/identity-subject.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { User } from './entities/user.entity';
import { GatewayController } from './gateway.controller';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { IdentityController } from './identity.controller';
import { resolveAccessTtlSeconds } from './services/access-ttl';
import { AuthService } from './services/auth.service';
import { ChallengeService } from './services/challenge.service';
import { EmailOtpService } from './services/email-otp.service';
import { GatewayTokenService } from './services/gateway-token.service';
import { GoogleOAuthService } from './services/google-oauth.service';
import { IdentityExchangeService } from './services/identity-exchange.service';
import { IdentityService } from './services/identity.service';
import { IdentitySubjectService } from './services/identity-subject.service';
import { IdentityTokenService } from './services/identity-token.service';
import { buildMailProvider, MailProvider } from './services/mail.provider';
import { SiweService } from './services/siwe.service';
import { TestAuthService } from './services/test-auth.service';
import { TokenService } from './services/token.service';

export function buildJwtOptions(configService: ConfigService) {
  const nodeEnv = configService.get<string>('NODE_ENV') ?? 'development';
  const secret = configService.get<string>('JWT_SECRET');
  // Fail closed everywhere except local development and unit tests: any
  // deployed environment (production, staging, ...) signing with a public
  // fallback secret would make access tokens forgeable.
  if (!secret && nodeEnv !== 'development' && nodeEnv !== 'test') {
    throw new Error(`JWT_SECRET is required when NODE_ENV is '${nodeEnv}'`);
  }
  const accessTtlSeconds = resolveAccessTtlSeconds(configService);
  return {
    secret: secret ?? 'cipherbox-dev-jwt-secret',
    signOptions: { expiresIn: accessTtlSeconds },
  };
}

@Module({
  imports: [
    TypeOrmModule.forFeature([User, AuthMethod, RefreshToken, GatewayToken, IdentitySubject]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: buildJwtOptions,
    }),
    OpsModule,
  ],
  controllers: [AuthController, GatewayController, IdentityController],
  providers: [
    AuthMetricsInterceptor,
    AuthService,
    TestAuthService,
    TokenService,
    GatewayTokenService,
    ChallengeService,
    IdentityService,
    SiweService,
    JwtAuthGuard,
    IdentityExchangeService,
    IdentitySubjectService,
    IdentityTokenService,
    GoogleOAuthService,
    EmailOtpService,
    { provide: MailProvider, useFactory: buildMailProvider, inject: [ConfigService] },
  ],
  // Shared, not re-provided: a second IdentityTokenService would hold a
  // different signing keypair wherever one is generated at boot, so every token
  // this module minted would fail verification elsewhere.
  exports: [TokenService, IdentityTokenService],
})
export class AuthModule {}
