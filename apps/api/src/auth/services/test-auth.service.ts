import { ForbiddenException, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { secp256k1 } from '@noble/curves/secp256k1';
import { createHash, timingSafeEqual } from 'node:crypto';
import { Repository } from 'typeorm';
import { Clock } from '../../common/clock';
import { AuthMethod } from '../entities/auth-method.entity';
import { User } from '../entities/user.entity';
import { IdentityService } from './identity.service';
import { TokenService } from './token.service';

export interface TestLoginResult {
  accessToken: string;
  refreshToken: string;
  gatewayToken: string;
  isNewUser: boolean;
  publicKey: string;
  privateKey: string;
}

/**
 * Staging-gated test-login (blueprint/api.md Ops; blueprint/testing.md
 * disposition table — the v1 pattern ports: prod hard-block, timing-safe
 * TEST_LOGIN_SECRET check, deterministic keypair).
 *
 * Never available in production regardless of env vars, and disabled
 * anywhere TEST_LOGIN_SECRET is unset.
 */
@Injectable()
export class TestAuthService {
  private readonly logger = new Logger(TestAuthService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly identityService: IdentityService,
    private readonly tokenService: TokenService,
    private readonly clock: Clock,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(AuthMethod)
    private readonly authMethodRepository: Repository<AuthMethod>
  ) {}

  async testLogin(handle: string, secret: string): Promise<TestLoginResult> {
    // Defense in depth: hard-block production regardless of configuration.
    if (this.configService.get<string>('NODE_ENV') === 'production') {
      throw new ForbiddenException('Test login is not available in production');
    }

    const expectedSecret = this.configService.get<string>('TEST_LOGIN_SECRET');
    if (!expectedSecret) {
      throw new ForbiddenException('Test login is not enabled');
    }
    // Hash both sides to a fixed 32 bytes before the constant-time compare —
    // a raw length pre-check would leak the secret's length through timing.
    const secretDigest = createHash('sha256').update(secret).digest();
    const expectedDigest = createHash('sha256').update(expectedSecret).digest();
    if (!timingSafeEqual(secretDigest, expectedDigest)) {
      throw new UnauthorizedException('Invalid test login secret');
    }

    const { publicKey, privateKey } = this.deriveDeterministicKeypair(handle);

    let user = await this.userRepository.findOne({ where: { publicKey } });
    const isNewUser = !user;
    if (!user) {
      user = await this.userRepository.save({ publicKey });
    }

    const identifierHash = this.identityService.hashIdentifier(this.normalizeHandle(handle));
    const existingMethod = await this.authMethodRepository.findOne({
      where: { kind: 'test', identifierHash },
    });
    if (existingMethod) {
      existingMethod.lastUsedAt = this.clock.now();
      await this.authMethodRepository.save(existingMethod);
    } else {
      await this.authMethodRepository.save({
        userId: user.id,
        kind: 'test',
        identifierHash,
        identifierDisplay: handle.slice(0, 255),
        lastUsedAt: this.clock.now(),
      });
    }

    const pair = await this.tokenService.createTokenPair(user.id, user.publicKey);
    this.logger.log(`Test login: userId=${user.id}, isNewUser=${isNewUser}`);

    return {
      accessToken: pair.accessToken,
      refreshToken: pair.refreshToken,
      gatewayToken: pair.gatewayToken,
      isNewUser,
      publicKey,
      privateKey,
    };
  }

  /**
   * Deterministic secp256k1 keypair from the handle: the same handle always
   * yields the same identity key, so e2e runs are reproducible.
   */
  private deriveDeterministicKeypair(handle: string): { publicKey: string; privateKey: string } {
    const seed = createHash('sha256')
      .update(`cipherbox-test-keypair:${this.normalizeHandle(handle)}`)
      .digest();

    // Clamp into [1, n-1] so the seed is a valid secp256k1 scalar.
    const n = secp256k1.CURVE.n;
    const scalar = (BigInt('0x' + seed.toString('hex')) % (n - 1n)) + 1n;
    const privateKey = scalar.toString(16).padStart(64, '0');
    const publicKey = Buffer.from(secp256k1.getPublicKey(privateKey, true)).toString('hex');
    return { publicKey, privateKey };
  }

  private normalizeHandle(handle: string): string {
    return handle.toLowerCase().trim();
  }
}
