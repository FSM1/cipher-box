import {
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, Not } from 'typeorm';
import * as jose from 'jose';
import Redis from 'ioredis';
import { parseSiweMessage } from 'viem/siwe';
import { REDIS_CLIENT } from '../../common/redis.module';
import { User } from '../entities/user.entity';
import { AuthMethod } from '../entities/auth-method.entity';
import { JwtIssuerService } from './jwt-issuer.service';
import { SiweService } from './siwe.service';
import { LinkMethodDto, AuthMethodResponseDto } from '../dto/link-method.dto';

@Injectable()
export class AuthMethodService {
  private readonly logger = new Logger(AuthMethodService.name);

  constructor(
    private jwtIssuerService: JwtIssuerService,
    private siweService: SiweService,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(AuthMethod)
    private authMethodRepository: Repository<AuthMethod>,
    @Inject(REDIS_CLIENT)
    private readonly redis: Redis
  ) {}

  /**
   * Get all linked auth methods for a user.
   * Returns identifierDisplay (human-readable) for all method types.
   * Falls back to '[redacted]' if identifierDisplay is not set.
   */
  async getLinkedMethods(userId: string): Promise<AuthMethodResponseDto[]> {
    const methods = await this.authMethodRepository.find({
      where: { userId },
      order: { createdAt: 'ASC' },
    });

    return methods.map((method) => ({
      id: method.id,
      type: method.type,
      // H-09: Fall back to '[redacted]' instead of leaking raw identifier hash
      identifier: method.identifierDisplay || '[redacted]',
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
   * Unlink an auth method from a user account.
   * Cannot unlink the last remaining auth method.
   */
  async unlinkMethod(userId: string, methodId: string): Promise<void> {
    await this.authMethodRepository.manager.transaction(async (manager) => {
      // 1. Lock all auth methods for this user to prevent concurrent unlinks
      const methods = await manager
        .createQueryBuilder(AuthMethod, 'am')
        .setLock('pessimistic_write')
        .where('am.userId = :userId', { userId })
        .getMany();

      // 2. Find the target method
      const method = methods.find((m) => m.id === methodId);
      if (!method) {
        throw new BadRequestException('Auth method not found');
      }

      // 3. Cannot unlink if only 1 method remains
      if (methods.length <= 1) {
        throw new BadRequestException('Cannot unlink your last auth method');
      }

      // 4. Delete the method
      await manager.remove(method);
    });
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

  /**
   * Link a Google or email auth method via CipherBox JWT verification.
   */
  private async linkJwtMethod(
    userId: string,
    linkDto: LinkMethodDto
  ): Promise<AuthMethodResponseDto[]> {
    // 1. Verify the CipherBox-issued JWT
    const payload = await this.verifyCipherBoxJwt(linkDto.idToken);

    // 2. Determine type and identifier, hash for lookup
    const authMethodType = linkDto.loginType;
    const identifier = payload.email || payload.sub;
    if (!identifier) {
      throw new BadRequestException('Cannot determine identifier from JWT');
    }
    const identifierHash = this.siweService.hashIdentifier(identifier);

    // 3. Check cross-account collision: same identifier linked to a different user
    const crossAccountMethod = await this.authMethodRepository.findOne({
      where: {
        type: authMethodType,
        identifierHash,
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
        identifierHash,
      },
    });

    if (existingMethod) {
      throw new BadRequestException('This auth method is already linked to your account');
    }

    // 5. Create new AuthMethod entity with hashed identifier
    await this.authMethodRepository.save({
      userId,
      type: authMethodType,
      identifier: identifierHash,
      identifierHash,
      identifierDisplay: payload.email ? this.siweService.truncateEmail(payload.email) : identifier,
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

    // 2. Verify SIWE signature with nonce consumption (C-01: prevent replay)
    const parsed = parseSiweMessage(linkDto.siweMessage);
    if (!parsed.nonce) {
      throw new BadRequestException('Invalid SIWE message: missing nonce');
    }

    // Consume nonce from Redis (single-use) — same pattern as identity.controller.ts walletLogin
    const nonceKey = `siwe:nonce:${parsed.nonce}`;
    let nonceDeleted: number;
    try {
      nonceDeleted = await this.redis.del(nonceKey);
    } catch (err) {
      this.logger.error('Redis error during nonce consumption', err);
      throw new BadRequestException('Nonce verification failed');
    }
    if (!nonceDeleted) {
      throw new BadRequestException('Invalid or expired nonce');
    }

    const walletAddress = await this.siweService.verifySiweMessage(
      linkDto.siweMessage,
      linkDto.siweSignature as `0x${string}`,
      parsed.nonce
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
}
