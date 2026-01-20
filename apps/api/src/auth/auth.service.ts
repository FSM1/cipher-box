import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, IsNull } from 'typeorm';
import * as argon2 from 'argon2';
import { User } from './entities/user.entity';
import { AuthMethod } from './entities/auth-method.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { Web3AuthVerifierService } from './services/web3auth-verifier.service';
import { TokenService } from './services/token.service';
import { LoginDto, LoginServiceResult } from './dto/login.dto';
import { RefreshServiceResult, LogoutResponseDto } from './dto/token.dto';

@Injectable()
export class AuthService {
  constructor(
    private web3AuthVerifier: Web3AuthVerifierService,
    private tokenService: TokenService,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(AuthMethod)
    private authMethodRepository: Repository<AuthMethod>,
    @InjectRepository(RefreshToken)
    private refreshTokenRepository: Repository<RefreshToken>
  ) {}

  async login(loginDto: LoginDto): Promise<LoginServiceResult> {
    // 1. Verify Web3Auth token
    const payload = await this.web3AuthVerifier.verifyIdToken(
      loginDto.idToken,
      loginDto.publicKey,
      loginDto.loginType
    );

    // 2. Find or create user
    let user = await this.userRepository.findOne({
      where: { publicKey: loginDto.publicKey },
    });

    const isNewUser = !user;
    if (!user) {
      user = await this.userRepository.save({
        publicKey: loginDto.publicKey,
      });
    }

    // 3. Find or create auth method
    const authMethodType = this.web3AuthVerifier.extractAuthMethodType(payload, loginDto.loginType);
    const identifier = this.web3AuthVerifier.extractIdentifier(payload);

    let authMethod = await this.authMethodRepository.findOne({
      where: {
        userId: user.id,
        type: authMethodType,
      },
    });

    if (!authMethod) {
      authMethod = await this.authMethodRepository.save({
        userId: user.id,
        type: authMethodType,
        identifier,
      });
    }

    // 4. Update last used timestamp
    authMethod.lastUsedAt = new Date();
    await this.authMethodRepository.save(authMethod);

    // 5. Create tokens
    const tokens = await this.tokenService.createTokens(user.id, user.publicKey);

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      isNewUser,
    };
  }

  async refresh(
    refreshToken: string,
    userId: string,
    publicKey: string
  ): Promise<RefreshServiceResult> {
    const tokens = await this.tokenService.rotateRefreshToken(refreshToken, userId, publicKey);

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  async logout(userId: string): Promise<LogoutResponseDto> {
    await this.tokenService.revokeAllUserTokens(userId);
    return { success: true };
  }

  /**
   * Refresh tokens by searching for the matching refresh token across all users.
   * This allows refresh without requiring the (possibly expired) access token.
   */
  async refreshByToken(refreshToken: string): Promise<RefreshServiceResult> {
    // Find all non-revoked, non-expired tokens
    const tokens = await this.refreshTokenRepository.find({
      where: {
        revokedAt: IsNull(),
      },
      relations: ['user'],
    });

    // Find matching token by verifying against hashes
    let validToken: RefreshToken | null = null;
    for (const token of tokens) {
      // Skip expired tokens
      if (token.expiresAt < new Date()) {
        continue;
      }
      try {
        if (await argon2.verify(token.tokenHash, refreshToken)) {
          validToken = token;
          break;
        }
      } catch {
        // argon2.verify throws on invalid hash format, continue checking
        continue;
      }
    }

    if (!validToken) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    // Revoke old token
    validToken.revokedAt = new Date();
    await this.refreshTokenRepository.save(validToken);

    // Create new tokens
    const newTokens = await this.tokenService.createTokens(
      validToken.userId,
      validToken.user.publicKey
    );

    return {
      accessToken: newTokens.accessToken,
      refreshToken: newTokens.refreshToken,
    };
  }
}
