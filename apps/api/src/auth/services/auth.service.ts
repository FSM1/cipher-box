import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { parseSiweMessage } from 'viem/siwe';
import { DataSource, EntityManager, IsNull, Not, Repository } from 'typeorm';
import {
  authMethodLockKey,
  boundedAcquire,
  resolveAdvisoryLockTimeoutMs,
  runLockGuardedTransaction,
  subjectLockKey,
} from '../../common/advisory-lock';
import { Clock } from '../../common/clock';
import { isUniqueViolation } from '../../common/pg-errors';
import { AccountDevice } from '../../device-approval/entities/account-device.entity';
import {
  AUTH_METHOD_IDENTIFIER_UNIQUE,
  AuthMethod,
  type AuthMethodKind,
} from '../entities/auth-method.entity';
import {
  IDENTITY_SUBJECT_IDENTIFIER_UNIQUE,
  IdentitySubject,
} from '../entities/identity-subject.entity';
import { User } from '../entities/user.entity';
import {
  ChallengeService,
  stepUpChallengeKind,
  type IdentityChallengeKind,
  type SiweChallengeKind,
  type StepUpOperation,
} from './challenge.service';
import { EmailOtpService, maskEmail } from './email-otp.service';
import { IdentityService } from './identity.service';
import { IdentityTokenService, type VerifiedIdentityToken } from './identity-token.service';
import { SIWE_LINK_STATEMENT, SiweService } from './siwe.service';
import { TokenPair, TokenService } from './token.service';

export interface LoginResult {
  pair: TokenPair;
  isNewUser: boolean;
}

/**
 * The kinds a link writes and an unlink can actually revoke: each has a display
 * row and a subject row that opens the account. `identity` and `test` authorise
 * off the `users` table rather than off `auth_methods`, and their login paths
 * re-insert the row on the next login — so deleting one would promise a
 * revocation the server does not perform.
 */
const LINKABLE_KINDS = ['wallet', 'email'] as const;

type LinkableKind = (typeof LINKABLE_KINDS)[number];

function isLinkable(kind: AuthMethodKind): kind is LinkableKind {
  return (LINKABLE_KINDS as readonly AuthMethodKind[]).includes(kind);
}

/** One login method in the display form `GET /auth/methods` serves. */
export interface AuthMethodView {
  id: string;
  kind: AuthMethodKind;
  identifierDisplay: string | null;
  createdAt: string;
  lastUsedAt: string | null;
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
    private readonly emailOtp: EmailOtpService,
    private readonly identityTokens: IdentityTokenService,
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
    return this.challengeService.issueIdentityChallenge('identity-login', {
      publicKey: canonicalKey,
    });
  }

  /**
   * Issue the re-proof challenge for one account-management operation. The key
   * comes from the caller's session, never from the request body, so a mint
   * cannot be aimed at another account's identity key. An unlink also names the
   * row it may remove: the signed bytes carry only the operation, so a captured
   * proof would otherwise authorise the removal of any method on the account.
   */
  issueStepUpChallenge(
    publicKey: string,
    operation: StepUpOperation,
    subject: string | undefined
  ): { challenge: string; expiresAt: Date } {
    if ((operation === 'unlink') !== (subject !== undefined)) {
      throw new BadRequestException(`methodId is required for an unlink, and for nothing else`);
    }
    const canonicalKey = this.identityService.normalizePublicKey(publicKey);
    return this.challengeService.issueIdentityChallenge(stepUpChallengeKind(operation), {
      publicKey: canonicalKey,
      subject,
    });
  }

  /**
   * Challenge-signature login. An `identityToken` from the exchange that preceded
   * this login binds an unbound account to an unbound subject (ADR 0058 D2); it is
   * not spent here.
   */
  async identityLogin(
    publicKey: string,
    challenge: string,
    signature: string,
    identityToken?: string
  ): Promise<LoginResult> {
    const canonicalKey = this.identityService.normalizePublicKey(publicKey);
    this.challengeService.consume(challenge, 'identity-login', { publicKey: canonicalKey });
    this.identityService.verifyChallengeSignature(challenge, signature, canonicalKey);

    let identity: VerifiedIdentityToken | null = null;
    if (identityToken !== undefined) {
      try {
        identity = await this.identityTokens.verify(identityToken);
      } catch {
        throw new UnauthorizedException('Invalid identity token');
      }
    }

    const { user, isNewUser } = await runLockGuardedTransaction(
      this.dataSource,
      async (manager) => {
        if (identity) {
          await boundedAcquire(manager, [subjectLockKey(identity.subject)], this.lockTimeoutMs);
        }
        const users = manager.getRepository(User);
        const existing = await users.findOne({ where: { publicKey: canonicalKey } });
        const bind =
          identity &&
          !existing?.identitySubjectId &&
          (await subjectIsFree(manager, identity.subject, existing?.id))
            ? identity.subject
            : null;
        const account =
          existing ?? (await users.save({ publicKey: canonicalKey, identitySubjectId: bind }));
        if (existing && bind) {
          // `IS NULL` keeps a concurrent bind of this account under another subject.
          await users.update(
            { id: existing.id, identitySubjectId: IsNull() },
            { identitySubjectId: bind }
          );
        }
        const methods = manager.getRepository(AuthMethod);
        const identifierHash = this.identityService.hashIdentifier(canonicalKey);
        const display = await methods.findOne({ where: { kind: 'identity', identifierHash } });
        await this.touchAuthMethod(methods, display, account.id, 'identity', {
          identifierHash,
          identifierDisplay: this.identityService.truncatePublicKey(canonicalKey),
        });
        return { user: account, isNewUser: !existing };
      }
    );
    if (isNewUser) {
      this.logger.log(`Account created implicitly at first login (userId=${user.id})`);
    }

    const pair = await this.tokenService.createTokenPair(user.id, user.publicKey);
    return { pair, isNewUser };
  }

  /** The identity subject bound to the account (ADR 0058 D1), read on the caller's transaction. */
  async boundSubjectOf(manager: EntityManager, userId: string): Promise<string | null> {
    const user = await manager
      .getRepository(User)
      .findOne({ where: { id: userId }, select: ['id', 'identitySubjectId'] });
    return user?.identitySubjectId ?? null;
  }

  /**
   * Issue a SIWE nonce. The link pool binds the minting account, so a nonce a
   * member's own session issued cannot be spent under another member's bearer;
   * the sign-in pool is unauthenticated and has no account to bind.
   */
  issueSiweNonce(kind: SiweChallengeKind, publicKey?: string): { nonce: string; expiresAt: Date } {
    const canonicalKey =
      publicKey === undefined ? undefined : this.identityService.normalizePublicKey(publicKey);
    return this.challengeService.issueSiweNonce(kind, { publicKey: canonicalKey });
  }

  /**
   * Link a SIWE wallet to the authenticated account (secondary method). The
   * identity challenge is re-proved first for the reason `unlinkAuthMethod`
   * states — adding a login method changes which keys open the account just as
   * removing one does, and the added method outlives the token that added it.
   */
  async siweLink(
    userId: string,
    publicKey: string,
    message: string,
    signature: `0x${string}`,
    challenge: string,
    challengeSignature: string
  ): Promise<void> {
    const canonicalKey = this.reproveAccountKey(
      publicKey,
      challenge,
      challengeSignature,
      'identity-link'
    );

    const nonce = parseSiweMessage(message).nonce;
    if (!nonce) {
      throw new UnauthorizedException('Invalid SIWE message: missing nonce');
    }
    this.challengeService.consume(nonce, 'siwe-link', { publicKey: canonicalKey });
    const address = await this.siweService.verifySiweMessage(
      message,
      signature,
      nonce,
      SIWE_LINK_STATEMENT
    );

    await this.linkMethod(
      userId,
      'wallet',
      {
        identifierHash: this.identityService.hashIdentifier(address),
        identifierDisplay: this.siweService.truncateWalletAddress(address),
      },
      'Wallet already opens this account',
      'Wallet is already linked to another account',
      'Wallet already opens another account'
    );
  }

  /** Send a code that only `emailLink` accepts, and only for this account. */
  sendEmailLinkCode(userId: string, email: string): Promise<void> {
    return this.emailOtp.send(email, 'link', userId);
  }

  /**
   * Link a passwordless email address to the authenticated account. The account
   * key is re-proved first, for the reason `siweLink` states.
   */
  async emailLink(
    userId: string,
    publicKey: string,
    email: string,
    code: string,
    challenge: string,
    challengeSignature: string
  ): Promise<void> {
    this.reproveAccountKey(publicKey, challenge, challengeSignature, 'identity-link');
    const address = this.emailOtp.verify(email, code, 'link', userId);

    await this.linkMethod(
      userId,
      'email',
      {
        identifierHash: this.identityService.hashIdentifier(address),
        identifierDisplay: maskEmail(address),
      },
      'Email already opens this account',
      'Email is already linked to another account'
    );
  }

  /**
   * Point a verified provider identity at the account's subject (ADR 0039 D1):
   * the display row and the `identity_subjects` row commit together or not at
   * all. The identity exchange hashes the same identifier, so the subject row
   * is the one a later sign-in through this method resolves. Any existing
   * subject row refuses the link, so every display row a link writes has the
   * one subject row the link wrote, and an unlink removes the two as a pair.
   */
  private async linkMethod(
    userId: string,
    kind: LinkableKind,
    identifiers: { identifierHash: string; identifierDisplay: string },
    opensThis: string,
    linkedElsewhere: string,
    opensAnother = linkedElsewhere
  ): Promise<void> {
    const { identifierHash } = identifiers;
    try {
      await runLockGuardedTransaction(this.dataSource, async (manager) => {
        const bound = await this.boundSubjectOf(manager, userId);
        if (bound === null) {
          throw new ConflictException('This account has no bound identity subject');
        }
        await boundedAcquire(
          manager,
          [authMethodLockKey(userId), subjectLockKey(bound)],
          this.lockTimeoutMs
        );
        const methods = manager.getRepository(AuthMethod);
        const display = await methods.findOne({ where: { kind, identifierHash } });
        if (display && display.userId !== userId) {
          throw new ConflictException(linkedElsewhere);
        }
        const subjects = manager.getRepository(IdentitySubject);
        const subject = await subjects.findOne({ where: { kind, identifierHash } });
        if (subject) {
          throw new ConflictException(subject.subjectId === bound ? opensThis : opensAnother);
        }

        await this.touchAuthMethod(methods, display, userId, kind, identifiers);
        await subjects.insert({
          kind,
          identifierHash,
          subjectId: bound,
          lastUsedAt: this.clock.now(),
        });
      });
    } catch (error) {
      // Another account's link, or an exchange, wrote the identifier after the reads above.
      if (isUniqueViolation(error, AUTH_METHOD_IDENTIFIER_UNIQUE)) {
        throw new ConflictException(linkedElsewhere);
      }
      if (isUniqueViolation(error, IDENTITY_SUBJECT_IDENTIFIER_UNIQUE)) {
        throw new ConflictException(opensAnother);
      }
      throw error;
    }
  }

  /**
   * The account's login methods for the settings pane. The projection stops at
   * the display columns, so `identifier_hash` never leaves the database — the
   * hash is what makes a stored identifier unlinkable to the account that owns
   * it, and serving it would undo that.
   */
  async listAuthMethods(userId: string): Promise<AuthMethodView[]> {
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
   * The unlink also deletes the subject row the link wrote, so a sign-in through
   * the method stops opening the account.
   */
  async unlinkAuthMethod(
    userId: string,
    publicKey: string,
    methodId: string,
    challenge: string,
    signature: string
  ): Promise<void> {
    this.reproveAccountKey(publicKey, challenge, signature, 'identity-unlink', methodId);

    await runLockGuardedTransaction(this.dataSource, async (manager) => {
      await boundedAcquire(manager, [authMethodLockKey(userId)], this.lockTimeoutMs);
      const repository = manager.getRepository(AuthMethod);
      // One read answers every refusal: whether the row is the caller's, what
      // kind it is, and whether it is the last one standing.
      const owned = await repository.find({
        where: { userId },
        select: ['id', 'kind', 'identifierHash'],
      });
      const target = owned.find((row) => row.id === methodId);
      if (!target) {
        throw new NotFoundException('Unknown login method');
      }
      if (!isLinkable(target.kind)) {
        throw new ConflictException(
          `A ${target.kind} login method cannot be unlinked: logging in through it recreates the row, so removing it would revoke nothing`
        );
      }
      if (owned.length <= 1) {
        throw new ConflictException('An account must keep at least one login method');
      }
      await repository.delete({ id: methodId, userId });
      await manager
        .getRepository(IdentitySubject)
        .delete({ kind: target.kind, identifierHash: target.identifierHash });
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

  /**
   * Consume a step-up challenge of `kind` and verify the account key's signature
   * over it. `subject` is the row an unlink names.
   */
  private reproveAccountKey(
    publicKey: string,
    challenge: string,
    signature: string,
    kind: IdentityChallengeKind,
    subject?: string
  ): string {
    const canonicalKey = this.identityService.normalizePublicKey(publicKey);
    this.challengeService.consume(challenge, kind, { publicKey: canonicalKey, subject });
    this.identityService.verifyChallengeSignature(challenge, signature, canonicalKey);
    return canonicalKey;
  }

  private async touchAuthMethod(
    repository: Repository<AuthMethod>,
    existing: AuthMethod | null,
    userId: string,
    kind: AuthMethodKind,
    identifiers: { identifierHash: string; identifierDisplay: string }
  ): Promise<void> {
    const lastUsedAt = this.clock.now();
    if (existing) {
      await repository.update({ id: existing.id }, { lastUsedAt });
      return;
    }
    await repository.insert({ userId, kind, ...identifiers, lastUsedAt });
  }
}

/**
 * Whether `subject` may bind to the account `userId`, or to the account this
 * login creates when `userId` is absent (ADR 0058 D2). The caller holds the
 * subject lock, so this check and the bind serialize.
 */
async function subjectIsFree(
  manager: EntityManager,
  subject: string,
  userId: string | undefined
): Promise<boolean> {
  if (await manager.getRepository(User).existsBy({ identitySubjectId: subject })) {
    return false;
  }
  // Device rows from before the bind landed still claim their subject.
  return !(await manager.getRepository(AccountDevice).existsBy({
    identitySubjectId: subject,
    ...(userId === undefined ? {} : { userId: Not(userId) }),
  }));
}
