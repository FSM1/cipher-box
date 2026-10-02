import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, QueryFailedError, Repository } from 'typeorm';
import { User } from '../../auth/entities/user.entity';
import {
  IdentityTokenService,
  type VerifiedIdentityToken,
} from '../../auth/services/identity-token.service';
import {
  boundedAcquire,
  registryLockKey,
  resolveAdvisoryLockTimeoutMs,
  runLockGuardedTransaction,
  subjectLockKey,
} from '../../common/advisory-lock';
import { Clock } from '../../common/clock';
import { positiveIntConfig } from '../../common/config-int';
import { UUID_RE } from '../../common/patterns';
import { deviceRegistrationPayload, verifyDeviceSignature } from '../device-signature';
import { ACCOUNT_DEVICE_PUBLIC_KEY_UNIQUE, AccountDevice } from '../entities/account-device.entity';

/** Bounds the table and the approval-prompt fan-out; via DEVICE_REGISTRY_CAP. */
const DEFAULT_DEVICE_CAP = 20;

/** Ceiling on the configured cap; an over-range value falls back to the default. */
const MAX_DEVICE_CAP = 100;

/** Postgres `unique_violation`. */
const UNIQUE_VIOLATION = '23505';

export interface RegisterDeviceInput {
  publicKey: string;
  signature: string;
  identityToken: string;
  label?: string;
}

export interface RegisteredDevice {
  id: string;
  publicKey: string;
  label: string | null;
  createdAt: string;
  lastSeenAt: string;
}

/**
 * The account's registered device identity keys (ADR 0009 D4) — what makes an
 * approval verifiable rather than self-reported. Revocation is a hard delete.
 */
@Injectable()
export class AccountDeviceService {
  private readonly lockTimeoutMs: number;
  private readonly deviceCap: number;

  constructor(
    @InjectRepository(AccountDevice)
    private readonly deviceRepository: Repository<AccountDevice>,
    @InjectDataSource()
    private readonly dataSource: DataSource,
    private readonly identityTokens: IdentityTokenService,
    private readonly clock: Clock,
    configService: ConfigService
  ) {
    this.lockTimeoutMs = resolveAdvisoryLockTimeoutMs(configService);
    this.deviceCap = positiveIntConfig(
      configService.get('DEVICE_REGISTRY_CAP'),
      DEFAULT_DEVICE_CAP,
      MAX_DEVICE_CAP
    );
  }

  /**
   * Register (or re-touch) this device's identity key. Idempotent per key: a
   * device that re-registers the same key updates its label and last-seen mark
   * rather than accumulating rows.
   */
  async register(userId: string, input: RegisterDeviceInput): Promise<RegisteredDevice> {
    if (
      !verifyDeviceSignature(
        input.publicKey,
        input.signature,
        deviceRegistrationPayload(userId, input.publicKey)
      )
    ) {
      throw new UnauthorizedException('Device signature does not verify');
    }

    let identity: VerifiedIdentityToken;
    try {
      identity = await this.identityTokens.verify(input.identityToken);
    } catch {
      throw new UnauthorizedException('Invalid identity token');
    }

    try {
      return await this.claim(userId, identity, input);
    } catch (error) {
      // The unique public-key index is the durable backstop under a concurrent
      // double-register: the loser's transaction aborts, so re-read the committed
      // winner on a fresh statement and answer as the unraced path would have.
      if (isPublicKeyConflict(error)) {
        const winner = await this.deviceRepository.findOne({
          where: { publicKey: input.publicKey },
        });
        if (winner && winner.userId !== userId) {
          throw new ConflictException('Device key is registered to another account');
        }
        if (winner) {
          return present(winner);
        }
      }
      throw error;
    }
  }

  /**
   * The lock spans both invariants this claim rests on. `subject:` serializes the
   * read of the bind against a login that writes it; `account:` serializes the
   * per-account cap, whose count and insert are separate statements and would
   * otherwise both pass at cap - 1.
   */
  private async claim(
    userId: string,
    identity: VerifiedIdentityToken,
    input: RegisterDeviceInput
  ): Promise<RegisteredDevice> {
    const identitySubjectId = identity.subject;
    return runLockGuardedTransaction(this.dataSource, async (manager) => {
      await boundedAcquire(
        manager,
        [subjectLockKey(identitySubjectId), registryLockKey(userId)],
        this.lockTimeoutMs
      );
      await this.identityTokens.spend(manager, identity);

      // ADR 0058 D3: the unique bind is what ties a subject to one account.
      const account = await manager
        .getRepository(User)
        .findOne({ where: { id: userId }, select: ['id', 'identitySubjectId'] });
      if (!account?.identitySubjectId) {
        throw new ConflictException('This account has no bound identity subject');
      }
      if (account.identitySubjectId !== identitySubjectId) {
        throw new ConflictException(
          'The identity token names a subject other than the one bound to this account'
        );
      }

      const repo = manager.getRepository(AccountDevice);
      const now = this.clock.now();

      const existing = await repo.findOne({ where: { publicKey: input.publicKey } });
      if (existing && existing.userId !== userId) {
        throw new ConflictException('Device key is registered to another account');
      }

      if (existing) {
        // The subject on a row is fixed at registration; a re-touch never rewrites it.
        if (existing.identitySubjectId !== identitySubjectId) {
          throw new ConflictException('Device key is registered under another identity');
        }
        existing.label = input.label ?? existing.label;
        existing.lastSeenAt = now;
        return present(await repo.save(existing));
      }

      if ((await repo.count({ where: { userId } })) >= this.deviceCap) {
        throw new ConflictException('Account has reached its registered-device limit');
      }

      return present(
        await repo.save({
          userId,
          identitySubjectId,
          publicKey: input.publicKey,
          label: input.label ?? null,
          createdAt: now,
          lastSeenAt: now,
        })
      );
    });
  }

  async list(userId: string): Promise<RegisteredDevice[]> {
    const rows = await this.deviceRepository.find({
      where: { userId },
      order: { createdAt: 'ASC' },
    });
    return rows.map(present);
  }

  /**
   * Hard delete, scoped to the caller's account. Idempotent and leak-free:
   * removing a gone or foreign id succeeds without side effects, so the route
   * is not an existence oracle for another account's device ids.
   */
  async revoke(userId: string, id: string): Promise<void> {
    if (!UUID_RE.test(id)) return;
    await this.deviceRepository.delete({ id, userId });
  }

  /**
   * The account a pre-reconstruction device reaches by presenting this identity:
   * the account bound to the subject (ADR 0058 D1), and only while it has a
   * registered device that can approve (ADR 0039 D3).
   */
  async accountForIdentitySubject(identitySubjectId: string): Promise<string | null> {
    const account = await this.dataSource
      .getRepository(User)
      .findOne({ where: { identitySubjectId }, select: ['id'] });
    if (!account) return null;
    return (await this.deviceRepository.existsBy({ userId: account.id })) ? account.id : null;
  }

  /** Whether this account has registered exactly this device key. */
  async isRegistered(userId: string, publicKey: string): Promise<boolean> {
    return (await this.deviceRepository.count({ where: { userId, publicKey } })) > 0;
  }
}

/** The lost race above and nothing else; any other fault must surface, not read as success. */
function isPublicKeyConflict(error: unknown): boolean {
  if (!(error instanceof QueryFailedError)) return false;
  const driver = error.driverError as { code?: string; constraint?: string } | undefined;
  return (
    driver?.code === UNIQUE_VIOLATION && driver?.constraint === ACCOUNT_DEVICE_PUBLIC_KEY_UNIQUE
  );
}

function present(row: AccountDevice): RegisteredDevice {
  return {
    id: row.id,
    publicKey: row.publicKey,
    label: row.label,
    createdAt: row.createdAt.toISOString(),
    lastSeenAt: row.lastSeenAt.toISOString(),
  };
}
