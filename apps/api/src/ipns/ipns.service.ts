import {
  Injectable,
  HttpException,
  HttpStatus,
  BadRequestException,
  ConflictException,
  Logger,
  Inject,
  forwardRef,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { FolderIpns } from './entities/folder-ipns.entity';
import {
  PublishIpnsDto,
  PublishIpnsEntryDto,
  PublishIpnsResponseDto,
  BatchPublishIpnsDto,
  BatchPublishIpnsResponseDto,
} from './dto';
import { RepublishService } from '../republish/republish.service';
import { DelegatedRoutingClient } from './delegated-routing.client';
import { MetricsService } from '../metrics/metrics.service';
import { parseIpnsRecord } from './ipns-record-parser';

@Injectable()
export class IpnsService {
  private readonly logger = new Logger(IpnsService.name);

  constructor(
    @InjectRepository(FolderIpns)
    private readonly folderIpnsRepository: Repository<FolderIpns>,
    private readonly delegatedRouting: DelegatedRoutingClient,
    @Inject(forwardRef(() => RepublishService))
    private readonly republishService: RepublishService,
    private readonly metricsService: MetricsService
  ) {}

  /**
   * Publish a pre-signed IPNS record to the IPFS network via delegated routing
   * and track the folder in the database for TEE republishing
   */
  async publishRecord(
    userId: string,
    dto: PublishIpnsDto | PublishIpnsEntryDto,
    recordType: 'folder' | 'file' = 'folder'
  ): Promise<PublishIpnsResponseDto> {
    const endTimer = this.metricsService.ipfsIpnsDuration.startTimer({
      operation: 'publish',
      source: '',
    });
    let result = 'success';

    try {
      // Validate base64 record
      let recordBytes: Uint8Array;
      try {
        recordBytes = Uint8Array.from(atob(dto.record), (c) => c.charCodeAt(0));
      } catch {
        throw new BadRequestException('Invalid base64-encoded record');
      }

      // Save to DB first so resolve always has a fallback, even if delegated
      // routing fails (e.g. rate-limited, network error, DHT propagation delay).
      const folder = await this.upsertFolderIpns(
        userId,
        dto.ipnsName,
        dto.metadataCid,
        dto.encryptedIpnsPrivateKey,
        dto.keyEpoch,
        recordType,
        dto.expectedSequenceNumber
      );

      // Publish to delegated routing API (fire-and-forget — DB is the reliable source).
      // DHT propagation via someguy takes ~10-30s per record. Since the DB record
      // is already saved and resolveRecord() always checks/prefers DB data, there is
      // no need to block the API response on DHT propagation. Metrics are still
      // collected via the detached promise chain (catch + then).
      const publishStart = process.hrtime.bigint();
      this.delegatedRouting
        .publish(dto.ipnsName, recordBytes)
        .catch((error) => {
          this.logger.warn(
            `Delegated routing publish failed for ${dto.ipnsName}, DB record saved: ${error instanceof Error ? error.message : String(error)}`
          );
          return 'error' as const;
        })
        .then((outcome) => {
          const publishElapsed = Number(process.hrtime.bigint() - publishStart) / 1e9;
          this.metricsService.ipnsPublishDuration.observe(
            { outcome: outcome === 'error' ? 'error' : 'success' },
            publishElapsed
          );
        })
        .catch((error) => {
          this.logger.error(
            `Failed to record IPNS publish metrics for ${dto.ipnsName}: ${error instanceof Error ? error.message : String(error)}`
          );
        });

      return {
        success: true,
        ipnsName: dto.ipnsName,
        sequenceNumber: folder.sequenceNumber,
      };
    } catch (error) {
      result = 'error';
      throw error;
    } finally {
      endTimer({ result });
    }
  }

  /**
   * Batch publish multiple IPNS records with concurrency-limited processing.
   * Supports partial success: individual record failures do not fail the batch.
   * Processes up to 10 records concurrently.
   */
  async publishBatch(
    userId: string,
    dto: BatchPublishIpnsDto
  ): Promise<BatchPublishIpnsResponseDto> {
    const results: PublishIpnsResponseDto[] = [];
    let totalSucceeded = 0;
    let totalFailed = 0;

    const CONCURRENCY = 10;

    // Process records in batches of CONCURRENCY, delegating to publishRecord
    for (let i = 0; i < dto.records.length; i += CONCURRENCY) {
      const batch = dto.records.slice(i, i + CONCURRENCY);

      const settled = await Promise.allSettled(
        batch.map((entry) => this.publishRecord(userId, entry, entry.recordType ?? 'folder'))
      );

      for (let j = 0; j < settled.length; j++) {
        const result = settled[j];
        if (result.status === 'fulfilled') {
          results.push(result.value);
          totalSucceeded++;
        } else {
          const reason = result.reason;
          // If any record (especially a folder record) has a conflict, fail the entire batch
          if (reason instanceof ConflictException) {
            throw reason;
          }
          const ipnsName = batch[j]?.ipnsName ?? 'unknown';
          this.logger.warn(
            `Batch publish failed for ${ipnsName}: ${reason instanceof Error ? reason.message : String(reason)}`
          );
          results.push({
            success: false,
            ipnsName,
            sequenceNumber: '0',
          });
          totalFailed++;
        }
      }
    }

    return { results, totalSucceeded, totalFailed };
  }

  /**
   * Create or update a folder/file IPNS entry.
   * Handles both folder metadata and per-file metadata IPNS records.
   */
  private async upsertFolderIpns(
    userId: string,
    ipnsName: string,
    metadataCid: string,
    encryptedIpnsPrivateKey?: string,
    keyEpoch?: number,
    recordType: 'folder' | 'file' = 'folder',
    expectedSequenceNumber?: string
  ): Promise<FolderIpns> {
    const existing = await this.getFolderIpns(userId, ipnsName);

    // Conflict detection: when expectedSequenceNumber is provided, verify it matches
    if (existing && expectedSequenceNumber !== undefined) {
      const expected = BigInt(expectedSequenceNumber);
      const current = BigInt(existing.sequenceNumber);
      if (expected !== current) {
        throw new ConflictException({
          statusCode: 409,
          message: 'Sequence number mismatch: folder was modified by another device',
          currentSequenceNumber: existing.sequenceNumber,
          expectedSequenceNumber,
        });
      }
    }

    if (existing) {
      // Update existing entry
      existing.latestCid = metadataCid;
      existing.sequenceNumber = (BigInt(existing.sequenceNumber) + 1n).toString();
      existing.recordType = recordType;
      existing.updatedAt = new Date();

      // Only update encrypted key if provided (e.g., on key rotation)
      if (encryptedIpnsPrivateKey && keyEpoch !== undefined) {
        existing.encryptedIpnsPrivateKey = Buffer.from(encryptedIpnsPrivateKey, 'hex');
        existing.keyEpoch = keyEpoch;
      }

      const saved = await this.folderIpnsRepository.save(existing);

      // Auto-enroll for TEE republishing when encrypted key is provided
      if (encryptedIpnsPrivateKey && keyEpoch !== undefined) {
        this.republishService
          .enrollFolder(
            userId,
            ipnsName,
            Buffer.from(encryptedIpnsPrivateKey, 'hex'),
            keyEpoch,
            metadataCid,
            saved.sequenceNumber
          )
          .catch((err) =>
            this.logger.warn(
              `Failed to enroll ${recordType} ${ipnsName} for republishing: ${err.message}`
            )
          );
      }

      return saved;
    }

    // Create new entry — sequence starts at '1' to match the IPNS record
    // the client signed (clients compute newSeq = 0n + 1n = 1n for first publish).
    const folder = this.folderIpnsRepository.create({
      userId,
      ipnsName,
      latestCid: metadataCid,
      sequenceNumber: '1',
      encryptedIpnsPrivateKey: encryptedIpnsPrivateKey
        ? Buffer.from(encryptedIpnsPrivateKey, 'hex')
        : null,
      keyEpoch: keyEpoch ?? null,
      isRoot: false, // Root folder is tracked in Vault entity
      recordType,
    });

    const saved = await this.folderIpnsRepository.save(folder);

    // Auto-enroll for TEE republishing when encrypted key is provided
    if (encryptedIpnsPrivateKey && keyEpoch !== undefined) {
      this.republishService
        .enrollFolder(
          userId,
          ipnsName,
          Buffer.from(encryptedIpnsPrivateKey, 'hex'),
          keyEpoch,
          metadataCid,
          saved.sequenceNumber
        )
        .catch((err) =>
          this.logger.warn(
            `Failed to enroll ${recordType} ${ipnsName} for republishing: ${err.message}`
          )
        );
    }

    return saved;
  }

  /**
   * Get a folder IPNS entry by user and IPNS name
   */
  async getFolderIpns(userId: string, ipnsName: string): Promise<FolderIpns | null> {
    return this.folderIpnsRepository.findOne({
      where: { userId, ipnsName },
    });
  }

  /**
   * Get all folder IPNS entries for a user (for TEE republishing)
   */
  async getAllFolderIpns(userId: string): Promise<FolderIpns[]> {
    return this.folderIpnsRepository.find({
      where: { userId },
      order: { createdAt: 'ASC' },
    });
  }

  /**
   * Resolve an IPNS name to its current CID via delegated routing,
   * falling back to the DB-cached CID when delegated routing is unavailable
   * or when the record is not found in the DHT.
   * Returns null if the IPNS name is not found anywhere (404)
   */
  async resolveRecord(ipnsName: string): Promise<{
    cid: string;
    sequenceNumber: string;
    signatureV2?: string;
    data?: string;
    pubKey?: string;
  } | null> {
    const endTimer = this.metricsService.ipfsIpnsDuration.startTimer({
      operation: 'resolve',
    });
    let timerResult = 'success';
    let timerSource = 'network';
    const startTime = process.hrtime.bigint();
    let source = 'network';
    let resolveFound = false;

    try {
      let result: {
        cid: string;
        sequenceNumber: string;
        signatureV2?: string;
        data?: string;
        pubKey?: string;
      } | null = null;

      try {
        const recordBytes = await this.delegatedRouting.resolve(ipnsName);
        if (recordBytes) {
          result = this.parseIpnsRecordBytes(recordBytes);
          this.logger.debug(`IPNS name resolved successfully: ${ipnsName} -> ${result.cid}`);
        }
      } catch (error) {
        // Fall back to DB cache on BAD_GATEWAY (delegated routing failures)
        if (error instanceof HttpException && error.getStatus() === HttpStatus.BAD_GATEWAY) {
          this.logger.warn(`Delegated routing failed for ${ipnsName}, falling back to DB cache`);
          timerResult = 'error';
          source = 'db_cache';
        } else {
          timerResult = 'error';
          throw error;
        }
      }

      // Always check DB cache — it's written synchronously during publish
      // and may be ahead of the network (delegated routing can serve stale records)
      const cached = await this.folderIpnsRepository.findOne({
        where: { ipnsName },
      });

      if (result && cached?.latestCid) {
        // Both sources available — prefer the one with the higher sequence number
        const networkSeq = BigInt(result.sequenceNumber);
        const dbSeq = BigInt(cached.sequenceNumber);
        if (dbSeq > networkSeq) {
          this.logger.log(
            `DB cache has newer sequence (${dbSeq} > ${networkSeq}) for ${ipnsName}, using DB: ${cached.latestCid}`
          );
          timerSource = 'db';
          source = 'network_stale';
          resolveFound = true;
          return { cid: cached.latestCid, sequenceNumber: cached.sequenceNumber };
        }
        timerSource = 'network';
        resolveFound = true;
        return result;
      }

      if (result) {
        timerSource = 'network';
        resolveFound = true;
        return result;
      }

      // Delegated routing returned null (404) or threw BAD_GATEWAY — try DB cache
      if (cached?.latestCid) {
        this.logger.log(`Resolved ${ipnsName} from DB cache: ${cached.latestCid}`);
        timerSource = 'db';
        source = 'db_cache';
        resolveFound = true;
        return { cid: cached.latestCid, sequenceNumber: cached.sequenceNumber };
      }

      return null;
    } catch (error) {
      timerResult = 'error';
      throw error;
    } finally {
      endTimer({ result: timerResult, source: timerSource });
      if (resolveFound) {
        const elapsed = Number(process.hrtime.bigint() - startTime) / 1e9;
        this.metricsService.ipnsResolveDuration.observe({ source, outcome: timerResult }, elapsed);
      }
    }
  }

  /**
   * Parse an IPNS record to extract CID and sequence number
   * Uses inline protobuf decoder — no external dependencies
   */
  private parseIpnsRecordBytes(recordBytes: Uint8Array): {
    cid: string;
    sequenceNumber: string;
    signatureV2?: string;
    data?: string;
    pubKey?: string;
  } {
    try {
      const record = parseIpnsRecord(recordBytes);

      // Extract CID from the Value field (format: /ipfs/<cid>)
      const valuePath = record.value;
      const cidMatch = valuePath.match(/\/ipfs\/([a-zA-Z0-9]+)/);
      if (!cidMatch) {
        this.logger.error('Failed to extract CID from IPNS record value');
        throw new HttpException('Invalid IPNS record format', HttpStatus.BAD_GATEWAY);
      }

      const cid = cidMatch[1];
      const sequenceNumber = String(record.sequence ?? 0n);

      // Base64-encode signature fields if present
      const signatureV2 = record.signatureV2
        ? Buffer.from(record.signatureV2).toString('base64')
        : undefined;
      const data = record.data ? Buffer.from(record.data).toString('base64') : undefined;
      const pubKey = record.pubKey ? Buffer.from(record.pubKey).toString('base64') : undefined;

      this.logger.debug(`Parsed IPNS record: cid=${cid}, sequenceNumber=${sequenceNumber}`);
      return { cid, sequenceNumber, signatureV2, data, pubKey };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      this.logger.error(`Failed to parse IPNS record: ${error}`);
      throw new HttpException('Invalid IPNS record format', HttpStatus.BAD_GATEWAY);
    }
  }
}
