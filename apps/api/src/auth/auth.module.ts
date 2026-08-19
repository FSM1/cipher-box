import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthController } from './auth.controller';
import { AuthMethod } from './entities/auth-method.entity';
import { IdentitySubject } from './entities/identity-subject.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { User } from './entities/user.entity';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { IdentityController } from './identity.controller';
import { AuthService } from './services/auth.service';
import { ChallengeService } from './services/challenge.service';
import { EmailOtpService } from './services/email-otp.service';
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
  const accessTtlSeconds = Number(configService.get('ACCESS_TOKEN_TTL_SECONDS') ?? 900);
  return {
    secret: secret ?? 'cipherbox-dev-jwt-secret',
    signOptions: { expiresIn: accessTtlSeconds },
  };
}

@Module({
  imports: [
    TypeOrmModule.forFeature([User, AuthMethod, RefreshToken, IdentitySubject]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: buildJwtOptions,
    }),
  ],
  controllers: [AuthController, IdentityController],
  providers: [
    AuthService,
    TestAuthService,
    TokenService,
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
