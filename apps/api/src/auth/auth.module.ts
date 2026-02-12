import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { IdentityController } from './controllers/identity.controller';
import { AuthService } from './auth.service';
import { Web3AuthVerifierService } from './services/web3auth-verifier.service';
import { TokenService } from './services/token.service';
import { JwtIssuerService } from './services/jwt-issuer.service';
import { GoogleOAuthService } from './services/google-oauth.service';
import { EmailOtpService } from './services/email-otp.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { User } from './entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { AuthMethod } from './entities/auth-method.entity';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '15m' },
      }),
      inject: [ConfigService],
    }),
    TypeOrmModule.forFeature([User, RefreshToken, AuthMethod]),
  ],
  controllers: [AuthController, IdentityController],
  providers: [
    AuthService,
    Web3AuthVerifierService,
    TokenService,
    JwtIssuerService,
    GoogleOAuthService,
    EmailOtpService,
    JwtStrategy,
  ],
  exports: [AuthService, JwtModule],
})
export class AuthModule {}
