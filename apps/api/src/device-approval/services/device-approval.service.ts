import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  PayloadTooLargeException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, LessThanOrEqual, Repository } from 'typeorm';
import { IdentityTokenService } from '../../auth/services/identity-token.service';
import { ScopedToken, TokenService } from '../../auth/services/token.service';
import {
  advisoryLockKey,
  boundedAcquire,
  resolveAdvisoryLockTimeoutMs,
  runLockGuardedTransaction,
} from '../../common/advisory-lock';
import { Clock } from '../../common/clock';
import { positiveIntConfig } from '../../common/config-int';
import { DEFAULT_SWEEP_BATCH_SIZE, drainBatches, MAX_SWEEP_BATCH_SIZE } from '../../common/sweep';
import { UUID_RE } from '../../common/patterns';
import {
  approvalRequestPayload,
  approvalResponsePayload,
  verifyDeviceSignature,
  type ApprovalDecision,
} from '../device-signature';
import { DeviceApproval, DeviceApprovalStatus } from '../entities/device-approval.entity';
import { AccountDeviceService } from './account-device.service';

/** The abuse window the ADR bounds: v1's 5 minutes, kept; via DEVICE_APPROVAL_TTL_MS. */
const DEFAULT_TTL_MS = 5 * 60 * 1000;

/** Ceiling on the configured TTL; an over-range value falls back to the default. */
const MAX_TTL_MS = 60 * 60 * 1000;

/** Concurrent pending rendezvous per account; via DEVICE_APPROVAL_PENDING_CAP. */
const DEFAULT_PENDING_CAP = 5;

/** Ceiling on the configured cap; an over-range value falls back to the default. */
const MAX_PENDING_CAP = 50;

/** A sealed 32-byte factor is ~125 bytes under any sane AEAD; this is slack, not a budget. */
const MAX_SEALED_FACTOR_BYTES = 1024;

export interface CreateApprovalInput {
  devicePublicKey: string;
  ephemeralPublicKey: string;
  signature: string;
}

export interface RespondApprovalInput {
  decision: ApprovalDecision;
  devicePublicKey: string;
  signature: string;
  sealedFactor?: string;
}

export interface ApprovalStatus {
  status: DeviceApprovalStatus;
  ephemeralPublicKey: string;
  expiresAt: string;
  sealedFactor?: string;
  responderDevicePublicKey?: string;
  responseSignature?: string;
}

export interface PendingApproval {
  requestId: string;
  requesterDevicePublicKey: string;
  ephemeralPublicKey: string;
  requestSignature: string;
  createdAt: string;
  expiresAt: string;
}

/**
 * The device-approval rendezvous (ADR 0009 D1): a bulletin board that stores and
 * relays ciphertext and never holds plaintext key material.
 *
 * Both halves are bound to registered device keys (D4) — the request is signed
 * over the ephemeral key it offers, the response over the ephemeral key it
 * sealed to — so no check here rests on a self-reported identifier. A row dies
 * at collection or expiry, whichever comes first, and both are hard deletes.
 * Determinism is injected: every TTL cutoff comes from the Clock.
 */
@Injectable()
export class DeviceApprovalService {
  private readonly ttlMs: number;
  private readonly pendingCap: number;
  private readonly lockTimeoutMs: number;
  private readonly sweepBatchSize: number;

  constructor(
    @InjectRepository(DeviceApproval)
    private readonly approvalRepository: Repository<DeviceApproval>,
    @InjectDataSource()
    private readonly dataSource: DataSource,
    private readonly devices: AccountDeviceService,
    private readonly identityTokens: IdentityTokenService,
    private readonly tokens: TokenService,
    private readonly clock: Clock,
    configService: ConfigService
  ) {
    this.ttlMs = positiveIntConfig(
      configService.get('DEVICE_APPROVAL_TTL_MS'),
      DEFAULT_TTL_MS,
      MAX_TTL_MS
    );
    this.pendingCap = positiveIntConfig(
      configService.get('DEVICE_APPROVAL_PENDING_CAP'),
      DEFAULT_PENDING_CAP,
      MAX_PENDING_CAP
    );
    this.lockTimeoutMs = resolveAdvisoryLockTimeoutMs(configService);
    this.sweepBatchSize = positiveIntConfig(
      configService.get('DEVICE_APPROVAL_SWEEP_BATCH_SIZE'),
      DEFAULT_SWEEP_BATCH_SIZE,
      MAX_SWEEP_BATCH_SIZE
    );
  }

  /**
   * Mint the scoped pre-reconstruction token from a CipherBox identity token —
   * the only credential a device that cannot derive its key still holds. The
   * account is reached through a device already registered against that identity,
   * so an account nobody can approve for refuses here rather than opening a
   * rendezvous with no counterparty (the recovery phrase is that account's path,
   * ADR 0009 D2).
   */
  async openSession(identityToken: string): Promise<ScopedToken> {
    let subject: string;
    try {
      subject = (await this.identityTokens.verify(identityToken)).subject;
    } catch {
      throw new UnauthorizedException('Invalid identity token');
    }
    const userId = await this.devices.accountForIdentitySubject(subject);
    if (!userId) {
      throw new NotFoundException('No registered device can approve this identity');
    }
    return this.tokens.createScopedToken(userId, 'device-approval');
  }

  /**
   * Open a rendezvous. The signature binds the requesting device's identity key
   * to the ephemeral key it asks to have sealed to. That proves the pair is
   * internally consistent, NOT that it is the requester's — a relay can
   * substitute both halves and sign the substitute. Only the out-of-band
   * comparison value tells the two apart (ADR 0009 D3).
   */
  async createRequest(
    userId: string,
    input: CreateApprovalInput
  ): Promise<{ requestId: string; expiresAt: string }> {
    if (
      !verifyDeviceSignature(
        input.devicePublicKey,
        input.signature,
        approvalRequestPayload(input.devicePublicKey, input.ephemeralPublicKey)
      )
    ) {
      throw new UnauthorizedException('Request signature does not verify');
    }

    const now = this.clock.now();
    // Expired rows are dead fuel: purge before counting so an account whose cap
    // is full of stale rows can still open a rendezvous. Outside the transaction
    // below, whose cap refusal would otherwise roll the purge back with it.
    await this.purgeExpired(userId, now);

    return runLockGuardedTransaction(this.dataSource, async (manager) => {
      await boundedAcquire(manager, [rendezvousLockKey(userId)], this.lockTimeoutMs);
      const repo = manager.getRepository(DeviceApproval);

      if ((await repo.count({ where: { userId, status: 'pending' } })) >= this.pendingCap) {
        throw new ConflictException('Too many pending approval requests');
      }

      const saved = await repo.save({
        userId,
        requesterDevicePublicKey: input.devicePublicKey,
        ephemeralPublicKey: input.ephemeralPublicKey,
        requestSignature: input.signature,
        status: 'pending' as const,
        sealedFactor: null,
        responderDevicePublicKey: null,
        responseSignature: null,
        createdAt: now,
        expiresAt: new Date(now.getTime() + this.ttlMs),
      });
      return { requestId: saved.id, expiresAt: saved.expiresAt.toISOString() };
    });
  }

  /**
   * The requester's poll. A settled rendezvous is served exactly once — the
   * delete IS the claim, so two concurrent polls cannot both walk away with the
   * sealed bytes, and collection is what ends the row's life.
   */
  async status(userId: string, requestId: string): Promise<ApprovalStatus> {
    if (!UUID_RE.test(requestId)) {
      throw new NotFoundException('Unknown approval request');
    }
    const row = await this.approvalRepository.findOne({ where: { id: requestId, userId } });
    if (!row) {
      throw new NotFoundException('Unknown approval request');
    }
    if (row.expiresAt.getTime() <= this.clock.now().getTime()) {
      await this.approvalRepository.delete({ id: row.id, userId });
      throw new NotFoundException('Unknown approval request');
    }
    if (row.status === 'pending') {
      return {
        status: row.status,
        ephemeralPublicKey: row.ephemeralPublicKey,
        expiresAt: row.expiresAt.toISOString(),
      };
    }
    const claimed = await this.approvalRepository.delete({ id: row.id, userId });
    if (!claimed.affected) {
      throw new NotFoundException('Unknown approval request');
    }
    return {
      status: row.status,
      ephemeralPublicKey: row.ephemeralPublicKey,
      expiresAt: row.expiresAt.toISOString(),
      ...(row.sealedFactor
        ? { sealedFactor: Buffer.from(row.sealedFactor).toString('base64') }
        : {}),
      ...(row.responderDevicePublicKey
        ? { responderDevicePublicKey: row.responderDevicePublicKey }
        : {}),
      ...(row.responseSignature ? { responseSignature: row.responseSignature } : {}),
    };
  }

  /** Abandon a rendezvous: a hard delete, idempotent and scoped to the account. */
  async cancel(userId: string, requestId: string): Promise<void> {
    if (!UUID_RE.test(requestId)) return;
    await this.approvalRepository.delete({ id: requestId, userId });
  }

  /** What this account's registered devices are being asked to approve. */
  async pending(userId: string): Promise<PendingApproval[]> {
    const now = this.clock.now();
    await this.purgeExpired(userId, now);
    const rows = await this.approvalRepository.find({
      where: { userId, status: 'pending' },
      order: { createdAt: 'ASC' },
      take: this.pendingCap,
    });
    return rows.map((row) => ({
      requestId: row.id,
      requesterDevicePublicKey: row.requesterDevicePublicKey,
      ephemeralPublicKey: row.ephemeralPublicKey,
      requestSignature: row.requestSignature,
      createdAt: row.createdAt.toISOString(),
      expiresAt: row.expiresAt.toISOString(),
    }));
  }

  /**
   * Answer a rendezvous. The signature is checked over the ephemeral key AS
   * STORED, not as the caller reports it, so an approver's assent is bound to
   * the exact key the requester asked for. The approving key must be registered
   * to this account, which is the check v1 could not make.
   */
  async respond(userId: string, requestId: string, input: RespondApprovalInput): Promise<void> {
    if (!UUID_RE.test(requestId)) {
      throw new NotFoundException('Unknown approval request');
    }
    if (!(await this.devices.isRegistered(userId, input.devicePublicKey))) {
      throw new UnauthorizedException('Responding device is not registered to this account');
    }
    const sealed = this.decodeSealedFactor(input);

    const row = await this.approvalRepository.findOne({
      where: { id: requestId, userId, status: 'pending' },
    });
    if (!row) {
      throw new NotFoundException('Unknown approval request');
    }
    if (row.expiresAt.getTime() <= this.clock.now().getTime()) {
      await this.approvalRepository.delete({ id: row.id, userId });
      throw new NotFoundException('Unknown approval request');
    }
    if (row.requesterDevicePublicKey === input.devicePublicKey) {
      throw new BadRequestException('A device cannot approve its own request');
    }
    if (
      !verifyDeviceSignature(
        input.devicePublicKey,
        input.signature,
        approvalResponsePayload({
          devicePublicKey: input.devicePublicKey,
          requestId: row.id,
          decision: input.decision,
          ephemeralPublicKey: row.ephemeralPublicKey,
          sealedFactor: input.sealedFactor ?? '',
        })
      )
    ) {
      throw new UnauthorizedException('Response signature does not verify');
    }

    // The conditional update IS the single-answer claim: two approvers racing the
    // same rendezvous both verify, and only the one still finding it pending writes.
    const claim = await this.approvalRepository.update(
      { id: row.id, userId, status: 'pending' },
      {
        status: input.decision === 'approve' ? 'approved' : 'denied',
        sealedFactor: sealed,
        responderDevicePublicKey: input.devicePublicKey,
        responseSignature: input.signature,
      }
    );
    if (!claim.affected) {
      throw new NotFoundException('Unknown approval request');
    }
  }

  /** Lazy expiry purge for one account, matching the sweep's `expires_at <= cutoff`. */
  private async purgeExpired(userId: string, cutoff: Date): Promise<void> {
    await this.approvalRepository.delete({ userId, expiresAt: LessThanOrEqual(cutoff) });
  }

  /**
   * The global TTL sweep the scheduled worker drives. The lazy purges above only
   * fire on an account's own traffic, so a rendezvous nobody returns to would
   * keep sealed material past its expiry — this makes the bound unconditional.
   *
   * The cutoff is one Clock snapshot for the whole run, and deletes are batched
   * by `ctid` so no run takes a long table lock. Returns the rows deleted.
   */
  async sweepExpired(): Promise<number> {
    const cutoff = this.clock.now();
    return drainBatches(this.sweepBatchSize, () => this.deleteExpiredBatch(cutoff));
  }

  /**
   * Postgres has no `DELETE ... LIMIT`, so the batch is bounded by selecting
   * `ctid`s under the cutoff and deleting exactly those; `expires_at` ordering
   * lets `idx_device_approvals_expires_at` drive the scan.
   */
  private async deleteExpiredBatch(cutoff: Date): Promise<number> {
    const result = await this.approvalRepository
      .createQueryBuilder()
      .delete()
      .from(DeviceApproval)
      .where(
        'ctid IN (SELECT ctid FROM device_approvals WHERE expires_at <= :cutoff ORDER BY expires_at LIMIT :limit)',
        { cutoff, limit: this.sweepBatchSize }
      )
      .execute();
    return result.affected ?? 0;
  }

  /** The sealed bytes, refusing a denial that carries them and an approval that does not. */
  private decodeSealedFactor(input: RespondApprovalInput): Buffer | null {
    if (input.decision === 'deny') {
      if (input.sealedFactor !== undefined) {
        throw new BadRequestException('A denial must not carry a sealed factor');
      }
      return null;
    }
    if (input.sealedFactor === undefined) {
      throw new BadRequestException('An approval must carry a sealed factor');
    }
    const sealed = Buffer.from(input.sealedFactor, 'base64');
    if (sealed.length === 0) {
      throw new BadRequestException('An approval must carry a sealed factor');
    }
    if (sealed.length > MAX_SEALED_FACTOR_BYTES) {
      throw new PayloadTooLargeException(`Sealed factor exceeds ${MAX_SEALED_FACTOR_BYTES} bytes`);
    }
    // The signature covers the TEXT while the row holds the bytes, so a spelling
    // that does not survive a decode/re-encode round trip would be served back
    // as a different string than the one the approver signed. Padding alone does
    // not settle it: `AB==` and `AA==` decode to the same byte.
    if (sealed.toString('base64') !== input.sealedFactor) {
      throw new BadRequestException('sealedFactor must be canonically encoded base64');
    }
    return sealed;
  }
}

/** Namespaced per `advisoryLockKey`'s shared bigint space. */
function rendezvousLockKey(userId: string): bigint {
  return advisoryLockKey(`device-approval:${userId}`);
}
