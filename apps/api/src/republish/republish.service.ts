import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, IsNull, LessThanOrEqual, Not, Repository } from 'typeorm';
import { IpnsRepublishSchedule } from './republish-schedule.entity';
import { IpnsRecord } from '../ipns/entities/ipns-record.entity';
import { TeeService, RepublishEntry, RepublishResult } from '../tee/tee.service';
import { TeeKeyStateService } from '../tee/tee-key-state.service';
import { DelegatedRoutingClient } from '../ipns/delegated-routing.client';

/** Max entries per TEE request -- increased for per-file IPNS scalability (file records are smaller payloads) */
const BATCH_SIZE = 100;

/** After this many consecutive failures, mark entry as 'stale' */
const MAX_CONSECUTIVE_FAILURES = 10;

/** Republish interval in hours */
const REPUBLISH_INTERVAL_HOURS = 6;

/** Max backoff cap in seconds */
const MAX_BACKOFF_SECONDS = 3600;

/** Base backoff in seconds */
const BASE_BACKOFF_SECONDS = 30;

/** Paired result from getDueEntries — canonical record sourced directly from ipns_records */
export interface DueEntryPair {
  schedule: IpnsRepublishSchedule;
  record: IpnsRecord;
}

@Injectable()
export class RepublishService {
  private readonly logger = new Logger(RepublishService.name);

  constructor(
    @InjectRepository(IpnsRepublishSchedule)
    private readonly scheduleRepository: Repository<IpnsRepublishSchedule>,
    @InjectRepository(IpnsRecord)
    private readonly ipnsRecordRepository: Repository<IpnsRecord>,
    private readonly teeService: TeeService,
    private readonly teeKeyStateService: TeeKeyStateService,
    private readonly delegatedRouting: DelegatedRoutingClient
  ) {}

  /**
   * Query entries that are due for republishing, inner-joining ipns_records.
   *
   * D-02 / TEE-03: only schedule rows with a matching ipns_records row that is
   * NOT tombstoned AND has an encrypted IPNS key are returned. A tombstoned name
   * never enters the batch at this layer (defense layer 1).
   *
   * Returns an array of { schedule, record } pairs for each due entry.
   */
  async getDueEntries(): Promise<DueEntryPair[]> {
    // Step 1: due schedules via the find-options API (property names; robust
    // take-pagination — the query-builder + raw-column + take path trips a TypeORM
    // metadata error). LessThanOrEqual here selects rows due by time; it is NOT the
    // sequence write-back (that remains an equality CAS in renewIpnsRecordEol).
    const schedules = await this.scheduleRepository.find({
      where: {
        status: In(['active', 'retrying']),
        nextRepublishAt: LessThanOrEqual(new Date()),
      },
      order: { nextRepublishAt: 'ASC' },
      take: 2000,
    });

    if (schedules.length === 0) return [];

    // Step 2: fetch the matching ipns_records with the tombstone + key filter
    // (D-02 / TEE-03). A tombstoned or key-less record is excluded here, so its
    // schedule drops out of the paired result below — a tombstoned name never
    // enters the batch (defense layer 1; the renewal CAS is defense layer 2).
    // Pair schedule rows to ipns_records by BOTH userId and ipnsName. ipnsName
    // uniqueness is app-level, not a DB constraint (see the epoch-upgrade write
    // below), so keying the pairing on ipnsName alone could pair one user's schedule
    // with another user's record if two rows ever share a name. Scope by userId.
    const ipnsNames = [...new Set(schedules.map((s) => s.ipnsName))];
    const userIds = [...new Set(schedules.map((s) => s.userId))];
    const records = await this.ipnsRecordRepository.find({
      where: {
        userId: In(userIds),
        ipnsName: In(ipnsNames),
        tombstonedAt: IsNull(),
        encryptedIpnsPrivateKey: Not(IsNull()),
        // Also require the signing inputs so the teeEntries map below cannot deref a
        // null with `!`. A row missing either drops out here (re-picked next cycle)
        // instead of throwing outside the inner try and aborting the whole batch.
        signedRecord: Not(IsNull()),
        keyEpoch: Not(IsNull()),
      },
    });

    const pairKey = (userId: string, ipnsName: string) => `${userId}:${ipnsName}`;
    const recordMap = new Map(records.map((r) => [pairKey(r.userId, r.ipnsName), r]));

    return schedules
      .map((schedule) => {
        const record = recordMap.get(pairKey(schedule.userId, schedule.ipnsName));
        if (!record) return null; // race: tombstoned or key removed between the two queries
        return { schedule, record };
      })
      .filter((p): p is DueEntryPair => p !== null);
  }

  /**
   * Main orchestration: process all due republish entries.
   * Batches entries, sends to TEE for signing, publishes signed records.
   */
  async processRepublishBatch(): Promise<{
    processed: number;
    succeeded: number;
    failed: number;
  }> {
    const duePairs = await this.getDueEntries();

    if (duePairs.length === 0) {
      this.logger.debug('No entries due for republishing');
      return { processed: 0, succeeded: 0, failed: 0 };
    }

    this.logger.log(`Processing ${duePairs.length} due republish entries`);

    // Soft capacity warning for large vaults with many per-file IPNS records
    if (duePairs.length > 1000) {
      this.logger.warn(
        `High IPNS record count: ${duePairs.length} entries due for republishing - approaching capacity limits`
      );
    }

    let totalSucceeded = 0;
    let totalFailed = 0;

    // Split into batches of BATCH_SIZE
    for (let i = 0; i < duePairs.length; i += BATCH_SIZE) {
      const batch = duePairs.slice(i, i + BATCH_SIZE);

      // Build RepublishEntry payloads from the paired ipns_records row.
      // D-02 / TEE-03: ALL signing inputs come from the canonical ipns_records row —
      // no schedule snapshot fields, no relay-supplied epoch scalars (removed per D-03).
      const teeEntries: RepublishEntry[] = batch.map(({ schedule, record }) => ({
        encryptedIpnsPrivateKey: record.encryptedIpnsPrivateKey!.toString('base64'),
        keyEpoch: record.keyEpoch!,
        ipnsName: schedule.ipnsName,
        signedRecord: record.signedRecord!.toString('base64'),
      }));

      let teeResults: RepublishResult[];
      try {
        teeResults = await this.teeService.republish(teeEntries);
      } catch (error) {
        // TEE unreachable -- mark entire batch as failed
        const message = error instanceof Error ? error.message : String(error);
        this.logger.error(`TEE worker unreachable: ${message}`);

        for (const { schedule } of batch) {
          await this.handleEntryFailure(schedule, `TEE unreachable: ${message}`);
        }
        totalFailed += batch.length;
        continue;
      }

      // Process results
      for (let j = 0; j < batch.length; j++) {
        const { schedule, record } = batch[j];
        const result = teeResults[j];

        if (!result) {
          await this.handleEntryFailure(schedule, 'No result from TEE worker');
          totalFailed++;
          continue;
        }

        // requiresReEnroll: IPNS key can no longer be decrypted; log and route as failure
        // (consumer surface deferred to Phase 68/69 — non-fatal here).
        if (result.requiresReEnroll) {
          this.logger.warn(
            `TEE requires re-enrollment for ${schedule.ipnsName} — routing as failure (Phase 68/69)`
          );
          await this.handleEntryFailure(schedule, 'TEE requires re-enrollment');
          totalFailed++;
          continue;
        }

        if (result.success && result.signedRecord && result.newSequenceNumber) {
          // Defense-in-depth (TEE-02): the TEE must re-sign the SAME sequence. If it
          // returned a different sequence, publishing would push delegated routing ahead
          // of the canonical ipns_records row (whose renewal CAS only matches the loaded
          // sequence), leaving the two out of sync. Reject instead of publishing.
          if (result.newSequenceNumber !== record.sequenceNumber) {
            await this.handleEntryFailure(
              schedule,
              `TEE returned unexpected sequence ${result.newSequenceNumber}; expected ${record.sequenceNumber}`
            );
            totalFailed++;
            continue;
          }

          // TEE signing succeeded -- now publish to delegated routing
          try {
            await this.publishSignedRecord(schedule.ipnsName, result.signedRecord);

            // Update schedule entry: ONLY scheduling fields survive (no crypto columns).
            schedule.lastRepublishAt = new Date();
            schedule.consecutiveFailures = 0;
            schedule.status = 'active';
            schedule.lastError = null;
            schedule.nextRepublishAt = this.nextRepublishTime();

            await this.scheduleRepository.save(schedule);

            // EOL-only renewal write: update signed_record in ipns_records via
            // equality CAS. Uses the sequence number carried from getDueEntries
            // (NOT result.newSequenceNumber as a write target — seq is unchanged).
            // §6.6 / TEE-04: WHERE sequence_number = :loaded AND tombstoned_at IS NULL
            await this.renewIpnsRecordEol(
              schedule.ipnsName,
              record.userId, // scope the CAS to the owner (ipnsName is not globally unique)
              record.sequenceNumber, // loaded seq from the batch
              Buffer.from(result.signedRecord, 'base64')
            );

            // Epoch upgrade: re-encrypted key + new epoch go to ipns_records (not schedule).
            if (
              result.upgradedEncryptedKey !== undefined &&
              result.upgradedKeyEpoch !== undefined
            ) {
              this.logger.log(
                `Epoch upgrade for ${schedule.ipnsName}: epoch ${record.keyEpoch} -> ${result.upgradedKeyEpoch}`
              );
              // Scope the upgrade to the owner's non-tombstoned row at the loaded epoch:
              // - tombstonedAt: IsNull() preserves tombstone immutability (never re-encrypt
              //   a tombstoned row, even if it was tombstoned after the batch loaded)
              // - userId pins the owner (ipnsName uniqueness is app-level, not a DB constraint)
              // - keyEpoch equality is a CAS so a concurrent key rotation is not clobbered
              await this.ipnsRecordRepository.update(
                {
                  ipnsName: schedule.ipnsName,
                  userId: record.userId,
                  tombstonedAt: IsNull(),
                  keyEpoch: record.keyEpoch!, // non-null: getDueEntries filters keyEpoch IS NOT NULL
                },
                {
                  encryptedIpnsPrivateKey: Buffer.from(result.upgradedEncryptedKey, 'base64'),
                  keyEpoch: result.upgradedKeyEpoch,
                }
              );
            }

            totalSucceeded++;
          } catch (publishError) {
            // TEE signing succeeded but publishing failed (RESEARCH.md pitfall 6)
            const message =
              publishError instanceof Error ? publishError.message : String(publishError);
            this.logger.warn(
              `Signing succeeded but publish failed for ${schedule.ipnsName}: ${message}`
            );
            await this.handleEntryFailure(
              schedule,
              `Publish failed after successful signing: ${message}`
            );
            totalFailed++;
          }
        } else {
          // TEE signing failed
          await this.handleEntryFailure(schedule, result.error || 'Unknown TEE error');
          totalFailed++;
        }
      }
    }

    this.logger.log(
      `Republish batch complete: processed=${duePairs.length}, succeeded=${totalSucceeded}, failed=${totalFailed}`
    );

    return {
      processed: duePairs.length,
      succeeded: totalSucceeded,
      failed: totalFailed,
    };
  }

  /**
   * Publish a signed IPNS record to delegated routing with retries.
   */
  async publishSignedRecord(ipnsName: string, signedRecordBase64: string): Promise<void> {
    const recordBytes = Uint8Array.from(atob(signedRecordBase64), (c) => c.charCodeAt(0));
    await this.delegatedRouting.publish(ipnsName, recordBytes);
    this.logger.debug(`Signed IPNS record published for ${ipnsName}`);
  }

  /**
   * Enroll or update a folder for TEE republishing (scheduling-only).
   *
   * After 67-01 the schedule no longer stores signing columns — those live in
   * ipns_records. This method only manages the scheduling row: nextRepublishAt +
   * status/consecutiveFailures defaults on create.
   */
  async enrollFolder(userId: string, ipnsName: string): Promise<void> {
    const existing = await this.scheduleRepository.findOne({
      where: { userId, ipnsName },
    });

    if (existing) {
      // Refresh next republish time AND reactivate: a prior failure may have moved the
      // row out of the ['active','retrying'] set that getDueEntries selects, which would
      // leave a re-enrolled folder permanently excluded from the TEE batch.
      existing.nextRepublishAt = this.nextRepublishTime();
      existing.status = 'active';
      existing.consecutiveFailures = 0;
      existing.lastError = null;
      await this.scheduleRepository.save(existing);
      this.logger.log(`Updated republish enrollment for ${ipnsName}`);
    } else {
      const schedule = this.scheduleRepository.create({
        userId,
        ipnsName,
        nextRepublishAt: this.nextRepublishTime(),
        status: 'active',
        consecutiveFailures: 0,
        lastError: null,
        lastRepublishAt: null,
      });
      await this.scheduleRepository.save(schedule);
      this.logger.log(`Enrolled ${ipnsName} for TEE republishing`);
    }
  }

  /**
   * Unenroll an IPNS record from TEE republishing.
   * Called when files are deleted to prevent orphaned TEE enrollments.
   */
  async unenrollIpns(userId: string, ipnsName: string): Promise<number> {
    const result = await this.scheduleRepository.delete({ userId, ipnsName });
    const affected = result.affected ?? 0;
    if (affected > 0) {
      this.logger.log(`Unenrolled ${ipnsName} from TEE republishing for user ${userId}`);
    } else {
      this.logger.debug(
        `No republish enrollment found for ${ipnsName} (user ${userId}) - nothing to unenroll`
      );
    }
    return affected;
  }

  /**
   * Get aggregate health stats for admin endpoint.
   */
  async getHealthStats(): Promise<{
    pending: number;
    failed: number;
    stale: number;
    lastRunAt: Date | null;
    currentEpoch: number | null;
    teeHealthy: boolean;
  }> {
    const [pending, failed, stale] = await Promise.all([
      this.scheduleRepository.count({ where: { status: 'active' } }),
      this.scheduleRepository.count({ where: { status: 'retrying' } }),
      this.scheduleRepository.count({ where: { status: 'stale' } }),
    ]);

    // Get most recent successful republish
    const lastRun = await this.scheduleRepository.findOne({
      where: { status: 'active' },
      order: { lastRepublishAt: 'DESC' },
    });

    // Get current TEE epoch
    const teeState = await this.teeKeyStateService.getCurrentState();

    // Check TEE worker health
    let teeHealthy = false;
    try {
      const health = await this.teeService.getHealth();
      teeHealthy = health.healthy;
    } catch {
      teeHealthy = false;
    }

    return {
      pending,
      failed,
      stale,
      lastRunAt: lastRun?.lastRepublishAt ?? null,
      currentEpoch: teeState?.currentEpoch ?? null,
      teeHealthy,
    };
  }

  /**
   * Reactivate all stale entries (e.g., when TEE recovers).
   * Resets status to 'active' with immediate next republish time.
   */
  async reactivateStaleEntries(): Promise<number> {
    const result = await this.scheduleRepository.update(
      { status: 'stale' },
      {
        status: 'active',
        consecutiveFailures: 0,
        nextRepublishAt: new Date(),
        lastError: null,
      }
    );

    const count = result.affected ?? 0;
    if (count > 0) {
      this.logger.log(`Reactivated ${count} stale entries after TEE recovery`);
    }
    return count;
  }

  /**
   * Handle a failed entry: increment failures, apply backoff or mark stale.
   */
  private async handleEntryFailure(
    entry: IpnsRepublishSchedule,
    errorMessage: string
  ): Promise<void> {
    entry.consecutiveFailures += 1;
    // NEVER log key material -- only ipnsName, epoch, and failure count
    entry.lastError = errorMessage.substring(0, 500);

    if (entry.consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
      entry.status = 'stale';
      entry.nextRepublishAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // Far future
      this.logger.warn(
        `Entry ${entry.ipnsName} marked stale after ${entry.consecutiveFailures} failures`
      );
    } else {
      entry.status = 'retrying';
      const backoffSeconds = Math.min(
        BASE_BACKOFF_SECONDS * Math.pow(2, entry.consecutiveFailures),
        MAX_BACKOFF_SECONDS
      );
      entry.nextRepublishAt = new Date(Date.now() + backoffSeconds * 1000);
      this.logger.warn(
        `Entry ${entry.ipnsName} failed (${entry.consecutiveFailures}/${MAX_CONSECUTIVE_FAILURES}), retrying in ${backoffSeconds}s`
      );
    }

    await this.scheduleRepository.save(entry);
  }

  /**
   * EOL-only renewal write for the signed_record in ipns_records.
   *
   * §6.6 / TEE-04 carryover: uses the same equality-CAS shape as the
   * Phase-66 publish gate (sequence_number = :expected AND tombstoned_at IS NULL),
   * additionally scoped by user_id (ipnsName uniqueness is app-level, not a DB
   * constraint — so the CAS must pin the owner), but does NOT change sequence_number
   * — only signed_record and updatedAt are updated (lease-renewer: same CID, same
   * seq, later EOL bytes).
   *
   * On affected === 0: a forward publish raced the batch and already advanced
   * the sequence (or the row was tombstoned at the write level). Either way
   * the renewal is harmlessly discarded — the newer row already has a valid EOL.
   */
  private async renewIpnsRecordEol(
    ipnsName: string,
    userId: string,
    loadedSequenceNumber: string,
    renewedSignedRecord: Buffer
  ): Promise<void> {
    try {
      const result = await this.ipnsRecordRepository
        .createQueryBuilder()
        .update(IpnsRecord)
        .set({ signedRecord: renewedSignedRecord, updatedAt: new Date() })
        .where(
          'ipns_name = :ipnsName AND user_id = :userId AND sequence_number = :expected AND tombstoned_at IS NULL',
          {
            ipnsName,
            userId,
            expected: loadedSequenceNumber,
          }
        )
        .execute();

      if (result.affected === 0) {
        // Forward publish raced (seq advanced) OR tombstoned at the write level.
        // Either case: the renewal is harmlessly discarded.
        this.logger.debug(
          `EOL renewal CAS miss for ${ipnsName} (seq advanced or tombstoned) — discarding`
        );
      }
    } catch (error) {
      // A genuine DB error (connection loss, constraint violation) — NOT the
      // harmless affected===0 CAS-miss above. Surface at error level with a
      // message unambiguously distinct from the CAS-miss debug line so a real
      // write-back failure is observable and never masquerades as a CAS miss.
      // Still non-fatal: the IPNS publish already succeeded, so we log and
      // return rather than rethrow (totalSucceeded accounting is unchanged).
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(`renewIpnsRecordEol DB write-back failed for ${ipnsName}: ${message}`);
    }
  }

  /**
   * Calculate next republish time (now + 6 hours).
   */
  private nextRepublishTime(): Date {
    return new Date(Date.now() + REPUBLISH_INTERVAL_HOURS * 60 * 60 * 1000);
  }
}
