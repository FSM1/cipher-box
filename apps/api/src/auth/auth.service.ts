import {
  Injectable,
  Logger,
  UnauthorizedException,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { Repository, IsNull, Like, Not } from 'typeorm';
import { createECDH, createHash, timingSafeEqual } from 'crypto';
import * as jose from 'jose';
import * as argon2 from 'argon2';
import { User } from './entities/user.entity';
import { AuthMethod } from './entities/auth-method.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { JwtIssuerService } from './services/jwt-issuer.service';
import { TokenService } from './services/token.service';
import { SiweService } from './services/siwe.service';
import { LoginDto, LoginServiceResult } from './dto/login.dto';
import { RefreshServiceResult, LogoutResponseDto } from './dto/token.dto';
import { LinkMethodDto, AuthMethodResponseDto } from './dto/link-method.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private configService: ConfigService,
    private jwtIssuerService: JwtIssuerService,
    private tokenService: TokenService,
    private siweService: SiweService,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(AuthMethod)
    private authMethodRepository: Repository<AuthMethod>,
    @InjectRepository(RefreshToken)
    private refreshTokenRepository: Repository<RefreshToken>
  ) {}

  async login(loginDto: LoginDto): Promise<LoginServiceResult> {
    // 1. Verify CipherBox-issued JWT.
    // All auth methods now go through: CipherBox identity provider -> Core Kit loginWithJWT -> /auth/login.
    const payload = await this.verifyCipherBoxJwt(loginDto.idToken);

    // 2. Find or create user
    let user = await this.userRepository.findOne({
      where: { publicKey: loginDto.publicKey },
    });

    // 2b. Placeholder publicKey resolution for Core Kit identity provider.
    // When a user first authenticates via CipherBox identity provider,
    // they get a placeholder publicKey ('pending-core-kit-{userId}').
    // After Core Kit login, the client calls /auth/login with the REAL publicKey.
    // We need to find the placeholder user and update their publicKey.
    if (!user) {
      const verifierId = payload.verifierId || payload.sub;
      if (verifierId) {
        const placeholderUser = await this.userRepository.findOne({
          where: { publicKey: Like(`pending-core-kit-${verifierId}%`) },
        });
        if (placeholderUser) {
          this.logger.log(`Resolving placeholder publicKey for user ${placeholderUser.id}`);
          placeholderUser.publicKey = loginDto.publicKey;
          user = await this.userRepository.save(placeholderUser);
        }
      }
    }

    const isNewUser = !user;
    if (!user) {
      user = await this.userRepository.save({
        publicKey: loginDto.publicKey,
      });
    }

    // 3. Find or create auth method
    // The identity controller already created the auth method
    // (with the correct type: 'google', 'email', or 'wallet'). Look up by
    // userId + identifier to avoid creating duplicates with a hardcoded type.
    let authMethod: AuthMethod | null;

    const identifier = payload.email || payload.sub || 'unknown';
    authMethod = await this.authMethodRepository.findOne({
      where: { userId: user.id, identifier },
    });
    if (!authMethod) {
      // Fallback: find any auth method for this user (identity controller should have created one)
      authMethod = await this.authMethodRepository.findOne({
        where: { userId: user.id },
      });
    }
    if (!authMethod) {
      // Safety net: create auth method if identity controller didn't (shouldn't happen in practice)
      // All logins go through loginType='corekit' now, but infer type from identifier format
      const inferredType = identifier.startsWith('0x') ? 'wallet' : 'email';
      authMethod = await this.authMethodRepository.save({
        userId: user.id,
        type: inferredType,
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

  /**
   * Verify a CipherBox-issued JWT for Core Kit login flow.
   * Since we are the identity provider, we verify against our own JWKS.
   */
  private async verifyCipherBoxJwt(
    idToken: string
  ): Promise<{ sub?: string; verifierId?: string; email?: string }> {
    try {
      const jwksData = this.jwtIssuerService.getJwksData();
      const jwks = jose.createLocalJWKSet(jwksData);
      const { payload } = await jose.jwtVerify(idToken, jwks, {
        issuer: 'cipherbox',
        audience: 'web3auth',
        algorithms: ['RS256'],
      });
      return {
        sub: payload.sub,
        verifierId: payload.sub,
        email: payload.email as string | undefined,
      };
    } catch (error) {
      this.logger.warn(
        `CipherBox JWT verification failed: ${error instanceof Error ? error.message : 'unknown'}`
      );
      throw new UnauthorizedException('Invalid CipherBox identity token');
    }
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
    // Find candidate tokens by prefix for O(1) lookup instead of O(N) Argon2 scan
    const prefix = refreshToken.substring(0, 16);
    const tokens = await this.refreshTokenRepository.find({
      where: {
        tokenPrefix: prefix,
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

    // Look up user's email from their most recently used auth method
    // (covers both email and google auth methods)
    const emailMethod = await this.authMethodRepository.findOne({
      where: [
        { userId: validToken.userId, type: 'email' },
        { userId: validToken.userId, type: 'google' },
      ],
      order: { lastUsedAt: 'DESC' },
    });

    return {
      accessToken: newTokens.accessToken,
      refreshToken: newTokens.refreshToken,
      email: emailMethod?.identifier,
    };
  }

  /**
   * Get all linked auth methods for a user.
   * For wallet methods, returns the truncated display address (e.g. "0xAbCd...1234")
   * instead of the raw identifier hash.
   */
  async getLinkedMethods(userId: string): Promise<AuthMethodResponseDto[]> {
    const methods = await this.authMethodRepository.find({
      where: { userId },
      order: { createdAt: 'ASC' },
    });

    return methods.map((method) => ({
      id: method.id,
      type: method.type,
      identifier:
        method.type === 'wallet' && method.identifierDisplay
          ? method.identifierDisplay
          : method.identifier,
      lastUsedAt: method.lastUsedAt,
      createdAt: method.createdAt,
    }));
  }

  /**
   * Link a new auth method to an existing user account.
   *
   * For Google/email: verifies CipherBox-issued JWT to confirm ownership of the new method.
   * For wallet: verifies SIWE message+signature to confirm wallet ownership.
   *
   * Cross-account collision: if the auth method already belongs to a different user,
   * a BadRequestException is thrown (user must unlink from the other account first).
   */
  async linkMethod(userId: string, linkDto: LinkMethodDto): Promise<AuthMethodResponseDto[]> {
    // 1. Get the user
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const authMethodType = linkDto.loginType;

    if (authMethodType === 'wallet') {
      // Wallet linking: verify SIWE message + signature
      return this.linkWalletMethod(userId, linkDto);
    }

    // Google/email linking: verify CipherBox-issued JWT
    return this.linkJwtMethod(userId, linkDto);
  }

  /**
   * Link a Google or email auth method via CipherBox JWT verification.
   */
  private async linkJwtMethod(
    userId: string,
    linkDto: LinkMethodDto
  ): Promise<AuthMethodResponseDto[]> {
    // 1. Verify the CipherBox-issued JWT
    const payload = await this.verifyCipherBoxJwt(linkDto.idToken);

    // 2. Determine type and identifier
    const authMethodType = linkDto.loginType;
    const identifier = payload.email || payload.sub || 'unknown';

    // 3. Check cross-account collision: same identifier linked to a different user
    const crossAccountMethod = await this.authMethodRepository.findOne({
      where: {
        type: authMethodType,
        identifier,
        userId: Not(userId),
      },
    });

    if (crossAccountMethod) {
      throw new BadRequestException(
        `This ${authMethodType === 'google' ? 'Google account' : 'email'} is already linked to another account`
      );
    }

    // 4. Check if this exact method is already linked to this user
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
   * Link a wallet auth method via SIWE verification.
   */
  private async linkWalletMethod(
    userId: string,
    linkDto: LinkMethodDto
  ): Promise<AuthMethodResponseDto[]> {
    // 1. Validate required SIWE fields
    if (!linkDto.walletAddress || !linkDto.siweMessage || !linkDto.siweSignature) {
      throw new BadRequestException(
        'walletAddress, siweMessage, and siweSignature are required for wallet linking'
      );
    }

    // 2. Verify SIWE signature
    const domain = this.configService.get<string>('SIWE_DOMAIN', 'localhost');
    const { parseSiweMessage } = await import('viem/siwe');
    const parsed = parseSiweMessage(linkDto.siweMessage);
    if (!parsed.nonce) {
      throw new BadRequestException('Invalid SIWE message: missing nonce');
    }

    const walletAddress = await this.siweService.verifySiweMessage(
      linkDto.siweMessage,
      linkDto.siweSignature as `0x${string}`,
      parsed.nonce,
      domain
    );

    // 3. Hash the wallet address for lookup
    const addressHash = this.siweService.hashWalletAddress(walletAddress);

    // 4. Check cross-account collision: same wallet linked to a different user
    const crossAccountMethod = await this.authMethodRepository.findOne({
      where: {
        type: 'wallet',
        identifierHash: addressHash,
        userId: Not(userId),
      },
    });

    if (crossAccountMethod) {
      throw new BadRequestException('This wallet is already linked to another account');
    }

    // 5. Check if this wallet is already linked to this user
    const existingMethod = await this.authMethodRepository.findOne({
      where: {
        userId,
        type: 'wallet',
        identifierHash: addressHash,
      },
    });

    if (existingMethod) {
      throw new BadRequestException('This wallet is already linked to your account');
    }

    // 6. Create wallet auth method with hash + truncated display
    const truncated = this.siweService.truncateWalletAddress(walletAddress);
    await this.authMethodRepository.save({
      userId,
      type: 'wallet',
      identifier: addressHash,
      identifierHash: addressHash,
      identifierDisplay: truncated,
      lastUsedAt: new Date(),
    });

    // 7. Return updated list of methods
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

  /**
   * Test-only login that bypasses Core Kit entirely.
   * Guarded by TEST_LOGIN_SECRET env var — never available in production.
   *
   * Creates/finds user by email, generates a deterministic secp256k1 keypair,
   * and issues tokens. Returns the keypair so E2E tests can initialize vaults.
   */
  async testLogin(
    email: string,
    secret: string
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    isNewUser: boolean;
    publicKeyHex: string;
    privateKeyHex: string;
  }> {
    // 1. Defense-in-depth: never allow in production regardless of env var
    const nodeEnv = this.configService.get<string>('NODE_ENV');
    if (nodeEnv === 'production') {
      throw new ForbiddenException('Test login is not available in production');
    }

    // 2. Validate TEST_LOGIN_SECRET with timing-safe comparison
    const expectedSecret = this.configService.get<string>('TEST_LOGIN_SECRET');
    if (!expectedSecret) {
      throw new ForbiddenException('Test login is not enabled');
    }
    const secretBuf = Buffer.from(secret);
    const expectedBuf = Buffer.from(expectedSecret);
    if (secretBuf.length !== expectedBuf.length || !timingSafeEqual(secretBuf, expectedBuf)) {
      throw new UnauthorizedException('Invalid test login secret');
    }

    // 2. Generate deterministic secp256k1 keypair from email
    const { publicKeyHex, privateKeyHex } = this.generateDeterministicKeypair(email);

    // 3. Find or create user by email
    const normalizedEmail = email.toLowerCase().trim();

    const existingMethod = await this.authMethodRepository.findOne({
      where: { type: 'email', identifier: normalizedEmail },
      relations: ['user'],
    });

    let user: User;
    let isNewUser = false;

    if (existingMethod) {
      user = existingMethod.user;
      // Update publicKey to match deterministic keypair (may differ from Core Kit key)
      if (user.publicKey !== publicKeyHex) {
        user.publicKey = publicKeyHex;
        await this.userRepository.save(user);
      }
      existingMethod.lastUsedAt = new Date();
      await this.authMethodRepository.save(existingMethod);
    } else {
      isNewUser = true;
      user = await this.userRepository.save({ publicKey: publicKeyHex });
      await this.authMethodRepository.save({
        userId: user.id,
        type: 'email',
        identifier: normalizedEmail,
        lastUsedAt: new Date(),
      });
    }

    // 4. Issue tokens
    const tokens = await this.tokenService.createTokens(user.id, user.publicKey);

    this.logger.log(`Test login: userId=${user.id}, isNew=${isNewUser}`);

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      isNewUser,
      publicKeyHex,
      privateKeyHex,
    };
  }

  /**
   * Generate a deterministic secp256k1 keypair from an email address.
   * Same email always produces the same keypair, enabling consistent
   * vault encryption across test runs.
   */
  private generateDeterministicKeypair(email: string): {
    publicKeyHex: string;
    privateKeyHex: string;
  } {
    // Derive 32-byte private key from email via SHA-256
    const seed = createHash('sha256')
      .update(`cipherbox-test-keypair:${email.toLowerCase().trim()}`)
      .digest();

    // Ensure the seed is a valid secp256k1 private key (must be in [1, n-1])
    const n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
    let keyInt = BigInt('0x' + seed.toString('hex'));
    keyInt = (keyInt % (n - 1n)) + 1n;
    const privateKeyHex = keyInt.toString(16).padStart(64, '0');

    const ecdh = createECDH('secp256k1');
    ecdh.setPrivateKey(Buffer.from(privateKeyHex, 'hex'));
    const publicKeyHex = ecdh.getPublicKey().toString('hex'); // 65 bytes uncompressed

    return { publicKeyHex, privateKeyHex };
  }
}
