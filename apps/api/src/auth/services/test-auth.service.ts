import { Injectable, Logger, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { Repository } from 'typeorm';
import { createECDH, createHash, timingSafeEqual } from 'crypto';
import { User } from '../entities/user.entity';
import { AuthMethod } from '../entities/auth-method.entity';
import { TokenService } from './token.service';
import { SiweService } from './siwe.service';

@Injectable()
export class TestAuthService {
  private readonly logger = new Logger(TestAuthService.name);

  constructor(
    private configService: ConfigService,
    private tokenService: TokenService,
    private siweService: SiweService,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(AuthMethod)
    private authMethodRepository: Repository<AuthMethod>
  ) {}

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

    // 3. Find or create user by email (hash-based lookup)
    const normalizedEmail = email.toLowerCase().trim();
    const identifierHash = this.siweService.hashIdentifier(normalizedEmail);

    const existingMethod = await this.authMethodRepository.findOne({
      where: { type: 'email', identifierHash },
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
        identifier: identifierHash,
        identifierHash,
        identifierDisplay: this.siweService.truncateEmail(normalizedEmail),
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
