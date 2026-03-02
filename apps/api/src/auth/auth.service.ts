import {
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, IsNull } from 'typeorm';
import * as jose from 'jose';
import * as argon2 from 'argon2';
import { User } from './entities/user.entity';
import { AuthMethod } from './entities/auth-method.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { PinnedCid } from '../vault/entities/pinned-cid.entity';
import { IPFS_PROVIDER, IpfsProvider } from '../ipfs/providers/ipfs-provider.interface';
import { JwtIssuerService } from './services/jwt-issuer.service';
import { TokenService } from './services/token.service';
import { SiweService } from './services/siwe.service';
import { LoginDto, LoginServiceResult } from './dto/login.dto';
import { RefreshServiceResult, LogoutResponseDto } from './dto/token.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private jwtIssuerService: JwtIssuerService,
    private tokenService: TokenService,
    private siweService: SiweService,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(AuthMethod)
    private authMethodRepository: Repository<AuthMethod>,
    @InjectRepository(RefreshToken)
    private refreshTokenRepository: Repository<RefreshToken>,
    @InjectRepository(PinnedCid)
    private pinnedCidRepository: Repository<PinnedCid>,
    @Inject(IPFS_PROVIDER)
    private ipfsProvider: IpfsProvider
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
    //
    // Two scenarios need resolution:
    //
    // A) FIRST LOGIN completion: User was created with a placeholder publicKey
    //    ('pending-core-kit-{verifierId}') during identity token issuance.
    //    After Core Kit loginWithJWT, the client calls /auth/login with the
    //    REAL publicKey. Find the placeholder user and update their publicKey.
    //
    // B) REQUIRED_SHARE temp auth: MFA is enabled but the new device can't
    //    reconstruct the Core Kit key (missing device factor). The client
    //    sends a placeholder publicKey to get a temp access token for the
    //    device approval bulletin board. The user already has a REAL publicKey
    //    from their first login, so we look them up by identity (authMethod
    //    identifierHash) instead of by publicKey.
    if (!user) {
      const verifierId = payload.verifierId || payload.sub;

      if (verifierId) {
        // A) Check for user with placeholder publicKey (first login completion)
        const placeholderUser = await this.userRepository.findOne({
          where: { publicKey: `pending-core-kit-${verifierId}` },
        });
        if (placeholderUser) {
          this.logger.log(`Resolving placeholder publicKey for user ${placeholderUser.id}`);
          // Only update publicKey if the incoming key is a real one (not another placeholder)
          if (!loginDto.publicKey.startsWith('pending-core-kit-')) {
            placeholderUser.publicKey = loginDto.publicKey;
            user = await this.userRepository.save(placeholderUser);
          } else {
            user = placeholderUser;
          }
        }
      }

      // B) REQUIRED_SHARE temp auth: user already completed first login (has real
      //    publicKey), so no placeholder row exists. Look up directly by userId
      //    from the JWT sub — works for all auth method types (email, Google, wallet).
      if (!user && payload.sub && loginDto.publicKey.startsWith('pending-core-kit-')) {
        const existingUser = await this.userRepository.findOne({
          where: { id: payload.sub },
        });
        if (existingUser) {
          this.logger.log(
            `REQUIRED_SHARE temp auth: found existing user ${existingUser.id} by userId`
          );
          user = existingUser;
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
    // userId + identifierHash to avoid creating duplicates with a hardcoded type.
    let authMethod: AuthMethod | null;

    const identifier = payload.email || payload.sub;
    if (!identifier) {
      this.logger.warn('CipherBox JWT missing both email and sub claims');
      throw new UnauthorizedException('Invalid identity token: missing identifier');
    }
    const identifierHash = this.siweService.hashIdentifier(identifier);
    authMethod = await this.authMethodRepository.findOne({
      where: { userId: user.id, identifierHash },
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
      const display =
        inferredType === 'wallet'
          ? this.siweService.truncateWalletAddress(identifier)
          : this.siweService.truncateEmail(identifier);
      authMethod = await this.authMethodRepository.save({
        userId: user.id,
        type: inferredType,
        identifier: identifierHash,
        identifierHash,
        identifierDisplay: display,
      });
    }

    // 4. Update last used timestamp
    authMethod.lastUsedAt = new Date();
    await this.authMethodRepository.save(authMethod);

    // 5. Create tokens
    // REQUIRED_SHARE temp auth: issue scoped, non-refreshable tokens that only
    // grant access to the device-approval bulletin board. The new device will
    // do a second /auth/login with the real publicKey after key reconstruction.
    const isTempAuth = loginDto.publicKey.startsWith('pending-core-kit-') && !isNewUser;
    const tokens = await this.tokenService.createTokens(
      user.id,
      user.publicKey,
      isTempAuth ? { scope: ['device-approval'], skipRefreshToken: true } : undefined
    );

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
   * Permanently delete a user account and all associated data.
   *
   * 1. Unpins all IPFS content from the local Kubo node (best-effort)
   * 2. Deletes the user row — ON DELETE CASCADE handles cleanup of
   *    auth_methods, refresh_tokens, vaults, pinned_cids, folder_ipns,
   *    ipns_republish_schedule, shares, share_keys, and share_invites.
   */
  async deleteAccount(userId: string): Promise<{ success: boolean }> {
    // Fetch all pinned CIDs before cascade deletes the records
    const pinnedCids = await this.pinnedCidRepository.find({
      where: { userId },
      select: ['cid'],
    });

    // Unpin all content from Kubo (best-effort, don't block deletion on failure)
    if (pinnedCids.length > 0) {
      const results = await Promise.allSettled(
        pinnedCids.map((pin) => this.ipfsProvider.unpinFile(pin.cid))
      );
      const failed = results.filter((r) => r.status === 'rejected').length;
      this.logger.log(
        `Unpinned ${pinnedCids.length - failed}/${pinnedCids.length} CIDs for user ${userId}` +
          (failed > 0 ? ` (${failed} failed)` : '')
      );
    }

    // Delete user row — cascade handles all related DB records
    const result = await this.userRepository.delete(userId);
    if (result.affected === 0) {
      throw new BadRequestException('Account not found');
    }
    this.logger.log(`Account deleted: userId=${userId}`);
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
      // H-09: Fall back to undefined instead of leaking raw identifier hash
      email: emailMethod?.identifierDisplay || undefined,
    };
  }
}
