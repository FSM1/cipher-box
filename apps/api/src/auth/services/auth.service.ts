import {
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { parseSiweMessage } from 'viem/siwe';
import { DataSource, Repository } from 'typeorm';
import {
  authMethodLockKey,
  boundedAcquire,
  resolveAdvisoryLockTimeoutMs,
  runLockGuardedTransaction,
} from '../../common/advisory-lock';
import { Clock } from '../../common/clock';
import { AuthMethodDto } from '../dto/auth.dto';
import { AuthMethod } from '../entities/auth-method.entity';
import { User } from '../entities/user.entity';
import { ChallengeService } from './challenge.service';
import { IdentityService } from './identity.service';
import { SiweService } from './siwe.service';
import { TokenPair, TokenService } from './token.service';

export interface LoginResult {
  pair: TokenPair;
  isNewUser: boolean;
}

/**
 * Login orchestration (blueprint/api.md, Identity and auth + Account
 * lifecycle).
 *
 * The account IS the secp256k1 identity key: challenge-signature login is
 * the primary method and creates the account implicitly at first login.
 * SIWE stays as a secondary method — a wallet only authenticates an account
 * it was previously linked to by an authenticated session, so possession of
 * a wallet can never claim (or squat) an identity publicKey it does not own.
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly lockTimeoutMs: number;

  constructor(
    private readonly challengeService: ChallengeService,
    private readonly identityService: IdentityService,
    private readonly siweService: SiweService,
    private readonly tokenService: TokenService,
    private readonly clock: Clock,
    configService: ConfigService,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(AuthMethod)
    private readonly authMethodRepository: Repository<AuthMethod>,
    @InjectDataSource()
    private readonly dataSource: DataSource
  ) {
    this.lockTimeoutMs = resolveAdvisoryLockTimeoutMs(configService);
  }

  issueIdentityChallenge(publicKey: string): { challenge: string; expiresAt: Date } {
    const canonicalKey = this.identityService.normalizePublicKey(publicKey);
    return this.challengeService.issueIdentityChallenge(canonicalKey);
  }

  async identityLogin(
    publicKey: string,
    challenge: string,
    signature: string
  ): Promise<LoginResult> {
    const canonicalKey = this.identityService.normalizePublicKey(publicKey);
    this.challengeService.consume(challenge, 'identity', canonicalKey);
    this.identityService.verifyChallengeSignature(challenge, signature, canonicalKey);

    let user = await this.userRepository.findOne({ where: { publicKey: canonicalKey } });
    const isNewUser = !user;
    if (!user) {
      user = await this.userRepository.save({ publicKey: canonicalKey });
      this.logger.log(`Account created implicitly at first login (userId=${user.id})`);
    }

    await this.touchAuthMethod(user.id, 'identity', {
      identifierHash: this.identityService.hashIdentifier(canonicalKey),
      identifierDisplay: this.identityService.truncatePublicKey(canonicalKey),
    });

    const pair = await this.tokenService.createTokenPair(user.id, user.publicKey);
    return { pair, isNewUser };
  }

  issueSiweNonce(): { nonce: string; expiresAt: Date } {
    return this.challengeService.issueSiweNonce();
  }

  async siweLogin(message: string, signature: `0x${string}`): Promise<LoginResult> {
    const nonce = parseSiweMessage(message).nonce;
    if (!nonce) {
      throw new UnauthorizedException('Invalid SIWE message: missing nonce');
    }
    this.challengeService.consume(nonce, 'siwe');
    const address = await this.siweService.verifySiweMessage(message, signature, nonce);

    const identifierHash = this.siweService.hashWalletAddress(address);
    const method = await this.authMethodRepository.findOne({
      where: { kind: 'wallet', identifierHash },
    });
    if (!method) {
      // No implicit creation through SIWE: accounts are keyed by the
      // identity publicKey, which a bare wallet signature cannot prove.
      throw new UnauthorizedException('Wallet is not linked to an account');
    }

    const user = await this.userRepository.findOne({ where: { id: method.userId } });
    if (!user) {
      throw new UnauthorizedException('Wallet is not linked to an account');
    }

    method.lastUsedAt = this.clock.now();
    await this.authMethodRepository.save(method);

    const pair = await this.tokenService.createTokenPair(user.id, user.publicKey);
    return { pair, isNewUser: false };
  }

  /** Link a SIWE wallet to the authenticated account (secondary method). */
  async siweLink(userId: string, message: string, signature: `0x${string}`): Promise<void> {
    const nonce = parseSiweMessage(message).nonce;
    if (!nonce) {
      throw new UnauthorizedException('Invalid SIWE message: missing nonce');
    }
    this.challengeService.consume(nonce, 'siwe');
    const address = await this.siweService.verifySiweMessage(message, signature, nonce);

    const identifierHash = this.siweService.hashWalletAddress(address);
    const existing = await this.authMethodRepository.findOne({
      where: { kind: 'wallet', identifierHash },
    });
    if (existing && existing.userId !== userId) {
      throw new ConflictException('Wallet is already linked to another account');
    }

    await this.touchAuthMethod(userId, 'wallet', {
      identifierHash,
      identifierDisplay: this.siweService.truncateWalletAddress(address),
    });
  }

  /**
   * The account's login methods for the settings pane. The projection stops at
   * the display columns, so `identifier_hash` never leaves the database — the
   * hash is what makes a stored identifier unlinkable to the account that owns
   * it, and serving it would undo that.
   */
  async listAuthMethods(userId: string): Promise<AuthMethodDto[]> {
    const rows = await this.authMethodRepository.find({
      where: { userId },
      select: ['id', 'kind', 'identifierDisplay', 'createdAt', 'lastUsedAt'],
      order: { createdAt: 'DESC', id: 'DESC' },
    });
    return rows.map((row) => ({
      id: row.id,
      kind: row.kind,
      identifierDisplay: row.identifierDisplay,
      createdAt: row.createdAt.toISOString(),
      lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
    }));
  }

  /**
   * Unlink one login method. The identity challenge is re-proved first: a stolen
   * access token alone must not be able to strip an account's other login
   * methods, and only live possession of the account key can authorize it.
   */
  async unlinkAuthMethod(
    userId: string,
    publicKey: string,
    methodId: string,
    challenge: string,
    signature: string
  ): Promise<void> {
    const canonicalKey = this.identityService.normalizePublicKey(publicKey);
    this.challengeService.consume(challenge, 'identity', canonicalKey);
    this.identityService.verifyChallengeSignature(challenge, signature, canonicalKey);

    await runLockGuardedTransaction(this.dataSource, async (manager) => {
      await boundedAcquire(manager, [authMethodLockKey(userId)], this.lockTimeoutMs);
      const repository = manager.getRepository(AuthMethod);
      // One read answers both refusals: whether the row is the caller's, and
      // whether it is the last one standing.
      const owned = await repository.find({ where: { userId }, select: ['id'] });
      if (!owned.some((row) => row.id === methodId)) {
        throw new NotFoundException('Unknown login method');
      }
      if (owned.length <= 1) {
        throw new ConflictException('An account must keep at least one login method');
      }
      await repository.delete({ id: methodId, userId });
    });
  }

  async refresh(rawRefreshToken: string): Promise<TokenPair> {
    return this.tokenService.rotate(rawRefreshToken, async (userId) => {
      const user = await this.userRepository.findOne({ where: { id: userId } });
      if (!user) {
        throw new UnauthorizedException('Invalid refresh token');
      }
      return user.publicKey;
    });
  }

  async logout(userId: string): Promise<void> {
    await this.tokenService.revokeAllForUser(userId);
  }

  private async touchAuthMethod(
    userId: string,
    kind: AuthMethod['kind'],
    identifiers: { identifierHash: string; identifierDisplay: string }
  ): Promise<void> {
    const existing = await this.authMethodRepository.findOne({
      where: { kind, identifierHash: identifiers.identifierHash },
    });
    if (existing) {
      existing.lastUsedAt = this.clock.now();
      await this.authMethodRepository.save(existing);
      return;
    }
    await this.authMethodRepository.save({
      userId,
      kind,
      identifierHash: identifiers.identifierHash,
      identifierDisplay: identifiers.identifierDisplay,
      lastUsedAt: this.clock.now(),
    });
  }
}
