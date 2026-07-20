import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthController } from './auth.controller';
import { AuthMethod } from './entities/auth-method.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { User } from './entities/user.entity';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { AuthService } from './services/auth.service';
import { ChallengeService } from './services/challenge.service';
import { IdentityService } from './services/identity.service';
import { SiweService } from './services/siwe.service';
import { TestAuthService } from './services/test-auth.service';
import { TokenService } from './services/token.service';

export function buildJwtOptions(configService: ConfigService) {
  const nodeEnv = configService.get<string>('NODE_ENV') ?? 'development';
  const secret = configService.get<string>('JWT_SECRET');
  if (!secret && nodeEnv === 'production') {
    throw new Error('JWT_SECRET is required in production');
  }
  const accessTtlSeconds = Number(configService.get('ACCESS_TOKEN_TTL_SECONDS') ?? 900);
  return {
    secret: secret ?? 'cipherbox-dev-jwt-secret',
    signOptions: { expiresIn: accessTtlSeconds },
  };
}

@Module({
  imports: [
    TypeOrmModule.forFeature([User, AuthMethod, RefreshToken]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: buildJwtOptions,
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    TestAuthService,
    TokenService,
    ChallengeService,
    IdentityService,
    SiweService,
    JwtAuthGuard,
  ],
})
export class AuthModule {}
