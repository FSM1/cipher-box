import {
  Injectable,
  Logger,
  UnauthorizedException,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { Repository, IsNull, Like } from 'typeorm';
import { createECDH, createHash, timingSafeEqual } from 'crypto';
import * as jose from 'jose';
import * as argon2 from 'argon2';
import { User } from './entities/user.entity';
import { AuthMethod } from './entities/auth-method.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { Web3AuthVerifierService } from './services/web3auth-verifier.service';
import { JwtIssuerService } from './services/jwt-issuer.service';
import { TokenService } from './services/token.service';
import { LoginDto, LoginServiceResult } from './dto/login.dto';
import { RefreshServiceResult, LogoutResponseDto } from './dto/token.dto';
import { LinkMethodDto, AuthMethodResponseDto } from './dto/link-method.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private configService: ConfigService,
    private web3AuthVerifier: Web3AuthVerifierService,
    private jwtIssuerService: JwtIssuerService,
    private tokenService: TokenService,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(AuthMethod)
    private authMethodRepository: Repository<AuthMethod>,
    @InjectRepository(RefreshToken)
    private refreshTokenRepository: Repository<RefreshToken>
  ) {}

  async login(loginDto: LoginDto): Promise<LoginServiceResult> {
    // 1. Verify token based on login type
    let payload: {
      verifierId?: string;
      sub?: string;
      email?: string;
      verifier?: string;
      aggregateVerifier?: string;
      wallets?: { type: string; public_key?: string; address?: string; curve?: string }[];
    };

    if (loginDto.loginType === 'corekit') {
      // Core Kit login: verify the CipherBox-issued JWT using our own key.
      // The client already authenticated via /auth/identity/* endpoints,
      // received a CipherBox JWT, used it for Core Kit loginWithJWT,
      // and now sends it here for backend session creation.
      payload = await this.verifyCipherBoxJwt(loginDto.idToken);
    } else {
      // PnP / external wallet: verify Web3Auth-issued JWT
      const verificationKey =
        loginDto.loginType === 'external_wallet' && loginDto.walletAddress
          ? loginDto.walletAddress
          : loginDto.publicKey;

      payload = await this.web3AuthVerifier.verifyIdToken(
        loginDto.idToken,
        verificationKey,
        loginDto.loginType
      );
    }

    // 2. Find or create user
    let user = await this.userRepository.findOne({
      where: { publicKey: loginDto.publicKey },
    });

    // 2b. Placeholder publicKey resolution for Core Kit identity provider.
    // When a user first authenticates via CipherBox identity provider (Plan 12-01),
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
    const authMethodType =
      loginDto.loginType === 'corekit'
        ? 'email_passwordless'
        : this.web3AuthVerifier.extractAuthMethodType(payload, loginDto.loginType);
    const identifier =
      loginDto.loginType === 'corekit'
        ? payload.email || payload.sub || 'unknown'
        : this.web3AuthVerifier.extractIdentifier(payload);

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
    } else if (payload.email && authMethod.identifier !== payload.email) {
      // Backfill: update identifier if we now have the email but previously stored UUID
      authMethod.identifier = payload.email;
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
      throw new UnauthorizedException(
        `Invalid CipherBox identity token: ${error instanceof Error ? error.message : 'verification failed'}`
      );
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

    // Look up user's email from their most recently used email auth method
    const emailMethod = await this.authMethodRepository.findOne({
      where: { userId: validToken.userId, type: 'email_passwordless' },
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
      where: { type: 'email_passwordless', identifier: normalizedEmail },
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
        type: 'email_passwordless',
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
