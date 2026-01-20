import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
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
import { LinkMethodDto, AuthMethodResponseDto } from './dto/link-method.dto';

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
    // For external wallets, verify against wallet address (from JWT), not derived public key
    const verificationKey =
      loginDto.loginType === 'external_wallet' && loginDto.walletAddress
        ? loginDto.walletAddress
        : loginDto.publicKey;

    const payload = await this.web3AuthVerifier.verifyIdToken(
      loginDto.idToken,
      verificationKey,
      loginDto.loginType
    );

    // 2. Find or create user
    let user = await this.userRepository.findOne({
      where: { publicKey: loginDto.publicKey },
    });

    // Determine derivation version for external wallets (ADR-001)
    const derivationVersion =
      loginDto.loginType === 'external_wallet' ? (loginDto.derivationVersion ?? 1) : null;

    const isNewUser = !user;
    if (!user) {
      user = await this.userRepository.save({
        publicKey: loginDto.publicKey,
        derivationVersion,
      });
    } else if (user.derivationVersion !== derivationVersion) {
      // Update derivation version if changed (e.g., migration to v2)
      user.derivationVersion = derivationVersion;
      await this.userRepository.save(user);
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

  /**
   * Get all linked auth methods for a user.
   */
  async getLinkedMethods(userId: string): Promise<AuthMethodResponseDto[]> {
    const methods = await this.authMethodRepository.find({
      where: { userId },
      order: { createdAt: 'ASC' },
    });

    return methods.map((method) => ({
      id: method.id,
      type: method.type,
      identifier: method.identifier,
      lastUsedAt: method.lastUsedAt,
      createdAt: method.createdAt,
    }));
  }

  /**
   * Link a new auth method to an existing user account.
   * CRITICAL: The new auth method's publicKey must match the user's publicKey
   * (ensuring both auth methods derive the same keypair via Web3Auth group connections)
   */
  async linkMethod(userId: string, linkDto: LinkMethodDto): Promise<AuthMethodResponseDto[]> {
    // 1. Get the user to find their publicKey
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // 2. Verify the new idToken with Web3AuthVerifierService
    // This also validates that the new token's publicKey matches the user's publicKey
    const payload = await this.web3AuthVerifier.verifyIdToken(
      linkDto.idToken,
      user.publicKey,
      linkDto.loginType
    );

    // 3. Extract type and identifier from token payload
    const authMethodType = this.web3AuthVerifier.extractAuthMethodType(payload, linkDto.loginType);
    const identifier = this.web3AuthVerifier.extractIdentifier(payload);

    // 4. Check if this exact method (type + identifier) is already linked
    const existingMethod = await this.authMethodRepository.findOne({
      where: {
        userId,
        type: authMethodType,
        identifier,
      },
    });

    if (existingMethod) {
      throw new BadRequestException('This auth method is already linked to your account');
    }

    // 5. Create new AuthMethod entity
    await this.authMethodRepository.save({
      userId,
      type: authMethodType,
      identifier,
      lastUsedAt: new Date(),
    });

    // 6. Return updated list of methods
    return this.getLinkedMethods(userId);
  }

  /**
   * Unlink an auth method from a user account.
   * Cannot unlink the last remaining auth method.
   */
  async unlinkMethod(userId: string, methodId: string): Promise<void> {
    // 1. Find the method by id and userId
    const method = await this.authMethodRepository.findOne({
      where: { id: methodId, userId },
    });

    if (!method) {
      throw new BadRequestException('Auth method not found');
    }

    // 2. Count remaining methods for user
    const methodCount = await this.authMethodRepository.count({
      where: { userId },
    });

    // 3. Cannot unlink if only 1 method remains
    if (methodCount <= 1) {
      throw new BadRequestException('Cannot unlink your last auth method');
    }

    // 4. Delete the method
    await this.authMethodRepository.remove(method);
  }
}
