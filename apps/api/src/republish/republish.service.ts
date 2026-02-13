import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In, LessThanOrEqual } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { IpnsRepublishSchedule } from './republish-schedule.entity';
import { FolderIpns } from '../ipns/entities/folder-ipns.entity';
import { TeeService, RepublishEntry, RepublishResult } from '../tee/tee.service';
import { TeeKeyStateService } from '../tee/tee-key-state.service';

/** Max entries per TEE request (per RESEARCH.md pitfall 4) */
const BATCH_SIZE = 50;

/** After this many consecutive failures, mark entry as 'stale' */
const MAX_CONSECUTIVE_FAILURES = 10;

/** Republish interval in hours */
const REPUBLISH_INTERVAL_HOURS = 6;

/** Max backoff cap in seconds */
const MAX_BACKOFF_SECONDS = 3600;

/** Base backoff in seconds */
const BASE_BACKOFF_SECONDS = 30;

@Injectable()
export class RepublishService {
  private readonly logger = new Logger(RepublishService.name);
  private readonly delegatedRoutingUrl: string;
  private readonly maxPublishRetries = 3;
  private readonly publishBaseDelayMs = 1000;

  constructor(
    @InjectRepository(IpnsRepublishSchedule)
    private readonly scheduleRepository: Repository<IpnsRepublishSchedule>,
    @InjectRepository(FolderIpns)
    private readonly folderIpnsRepository: Repository<FolderIpns>,
    private readonly teeService: TeeService,
    private readonly teeKeyStateService: TeeKeyStateService,
    private readonly configService: ConfigService
  ) {
    this.delegatedRoutingUrl = this.configService.get<string>(
      'DELEGATED_ROUTING_URL',
      'https://delegated-ipfs.dev'
    );
  }

  /**
   * Query entries that are due for republishing.
   * Returns entries where status is 'active' or 'retrying' and next_republish_at <= now.
   */
  async getDueEntries(): Promise<IpnsRepublishSchedule[]> {
    return this.scheduleRepository.find({
      where: {
        status: In(['active', 'retrying']),
        nextRepublishAt: LessThanOrEqual(new Date()),
      },
      order: { nextRepublishAt: 'ASC' },
      take: 500,
    });
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
    const dueEntries = await this.getDueEntries();

    if (dueEntries.length === 0) {
      this.logger.debug('No entries due for republishing');
      return { processed: 0, succeeded: 0, failed: 0 };
    }

    this.logger.log(`Processing ${dueEntries.length} due republish entries`);

    // Fetch current TEE epoch state for the batch
    const teeState = await this.teeKeyStateService.getCurrentState();
    if (!teeState) {
      this.logger.error('TEE key state not initialized, cannot process republish batch');
      return { processed: dueEntries.length, succeeded: 0, failed: dueEntries.length };
    }

    const currentEpoch = teeState.currentEpoch;
    const previousEpoch = teeState.previousEpoch;

    let totalSucceeded = 0;
    let totalFailed = 0;

    // Split into batches of BATCH_SIZE
    for (let i = 0; i < dueEntries.length; i += BATCH_SIZE) {
      const batch = dueEntries.slice(i, i + BATCH_SIZE);

      // Build RepublishEntry payloads for TEE
      const teeEntries: RepublishEntry[] = batch.map((entry) => ({
        encryptedIpnsKey: entry.encryptedIpnsKey.toString('base64'),
        keyEpoch: entry.keyEpoch,
        ipnsName: entry.ipnsName,
        latestCid: entry.latestCid,
        sequenceNumber: entry.sequenceNumber,
        currentEpoch,
        previousEpoch,
      }));

      let teeResults: RepublishResult[];
      try {
        teeResults = await this.teeService.republish(teeEntries);
      } catch (error) {
        // TEE unreachable -- mark entire batch as failed
        const message = error instanceof Error ? error.message : String(error);
        this.logger.error(`TEE worker unreachable: ${message}`);

        for (const entry of batch) {
          await this.handleEntryFailure(entry, `TEE unreachable: ${message}`);
        }
        totalFailed += batch.length;
        continue;
      }

      // Process results
      for (let j = 0; j < batch.length; j++) {
        const entry = batch[j];
        const result = teeResults[j];

        if (!result) {
          await this.handleEntryFailure(entry, 'No result from TEE worker');
          totalFailed++;
          continue;
        }

        if (result.success && result.signedRecord && result.newSequenceNumber) {
          // TEE signing succeeded -- now publish to delegated routing
          try {
            await this.publishSignedRecord(entry.ipnsName, result.signedRecord);

            // Update schedule entry on success
            entry.sequenceNumber = result.newSequenceNumber;
            entry.lastRepublishAt = new Date();
            entry.consecutiveFailures = 0;
            entry.status = 'active';
            entry.lastError = null;
            entry.nextRepublishAt = this.nextRepublishTime();

            // Handle epoch upgrade if TEE re-encrypted with current epoch
            if (result.upgradedEncryptedKey && result.upgradedKeyEpoch !== undefined) {
              entry.encryptedIpnsKey = Buffer.from(result.upgradedEncryptedKey, 'base64');
              entry.keyEpoch = result.upgradedKeyEpoch;
              this.logger.log(
                `Epoch upgrade for ${entry.ipnsName}: epoch ${entry.keyEpoch} -> ${result.upgradedKeyEpoch}`
              );
            }

            await this.scheduleRepository.save(entry);

            // Keep FolderIpns sequence number in sync
            await this.syncFolderIpnsSequence(
              entry.userId,
              entry.ipnsName,
              result.newSequenceNumber
            );

            totalSucceeded++;
          } catch (publishError) {
            // TEE signing succeeded but publishing failed (RESEARCH.md pitfall 6)
            const message =
              publishError instanceof Error ? publishError.message : String(publishError);
            this.logger.warn(
              `Signing succeeded but publish failed for ${entry.ipnsName}: ${message}`
            );
            await this.handleEntryFailure(
              entry,
              `Publish failed after successful signing: ${message}`
            );
            totalFailed++;
          }
        } else {
          // TEE signing failed
          await this.handleEntryFailure(entry, result.error || 'Unknown TEE error');
          totalFailed++;
        }
      }
    }

    this.logger.log(
      `Republish batch complete: processed=${dueEntries.length}, succeeded=${totalSucceeded}, failed=${totalFailed}`
    );

    return {
      processed: dueEntries.length,
      succeeded: totalSucceeded,
      failed: totalFailed,
    };
  }

  /**
   * Publish a signed IPNS record to delegated routing with retries.
   */
  async publishSignedRecord(ipnsName: string, signedRecordBase64: string): Promise<void> {
    const url = `${this.delegatedRoutingUrl}/routing/v1/ipns/${ipnsName}`;
    const recordBytes = Uint8Array.from(atob(signedRecordBase64), (c) => c.charCodeAt(0));

    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.maxPublishRetries; attempt++) {
      try {
        const response = await fetch(url, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/vnd.ipfs.ipns-record',
          },
          body: recordBytes as unknown as BodyInit,
        });

        if (response.ok) {
          this.logger.debug(`Signed IPNS record published for ${ipnsName}`);
          return;
        }

        if (response.status === 429) {
          const retryAfter = response.headers.get('Retry-After');
          const delayMs = retryAfter
            ? parseInt(retryAfter, 10) * 1000
            : this.publishBaseDelayMs * Math.pow(2, attempt);
          this.logger.warn(`Rate limited on republish for ${ipnsName}, retrying in ${delayMs}ms`);
          await this.delay(delayMs);
          continue;
        }

        throw new Error(`Delegated routing returned ${response.status}`);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        if (attempt < this.maxPublishRetries - 1) {
          const delayMs = this.publishBaseDelayMs * Math.pow(2, attempt);
          this.logger.warn(
            `Republish attempt ${attempt + 1} failed for ${ipnsName}, retrying in ${delayMs}ms`
          );
          await this.delay(delayMs);
        }
      }
    }

    throw lastError || new Error('Publish failed after retries');
  }

  /**
   * Enroll or update a folder for TEE republishing.
   * Called when a folder is published with TEE-encrypted IPNS key.
   */
  async enrollFolder(
    userId: string,
    ipnsName: string,
    encryptedIpnsKey: Buffer,
    keyEpoch: number,
    latestCid: string,
    sequenceNumber: string
  ): Promise<void> {
    const existing = await this.scheduleRepository.findOne({
      where: { userId, ipnsName },
    });

    if (existing) {
      // Update existing enrollment
      existing.encryptedIpnsKey = encryptedIpnsKey;
      existing.keyEpoch = keyEpoch;
      existing.latestCid = latestCid;
      existing.sequenceNumber = sequenceNumber;
      existing.nextRepublishAt = this.nextRepublishTime();
      await this.scheduleRepository.save(existing);
      this.logger.log(`Updated republish enrollment for ${ipnsName}`);
    } else {
      // Create new enrollment
      const schedule = this.scheduleRepository.create({
        userId,
        ipnsName,
        encryptedIpnsKey,
        keyEpoch,
        latestCid,
        sequenceNumber,
        nextRepublishAt: this.nextRepublishTime(),
        status: 'active',
        consecutiveFailures: 0,
        lastError: null,
        lastRepublishAt: null,
      });
      await this.scheduleRepository.save(schedule);
      this.logger.log(`Enrolled ${ipnsName} for TEE republishing (epoch ${keyEpoch})`);
    }
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
   * Sync the FolderIpns sequence number after successful republish.
   */
  private async syncFolderIpnsSequence(
    userId: string,
    ipnsName: string,
    newSequenceNumber: string
  ): Promise<void> {
    try {
      await this.folderIpnsRepository.update(
        { userId, ipnsName },
        { sequenceNumber: newSequenceNumber }
      );
    } catch (error) {
      // Non-fatal: log and continue
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`Failed to sync FolderIpns sequence for ${ipnsName}: ${message}`);
    }
  }

  /**
   * Calculate next republish time (now + 6 hours).
   */
  private nextRepublishTime(): Date {
    return new Date(Date.now() + REPUBLISH_INTERVAL_HOURS * 60 * 60 * 1000);
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
