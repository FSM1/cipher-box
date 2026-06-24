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
import { deriveIpnsName, parseIpnsRecord, verifyIpnsRecordSignature } from '@cipherbox/crypto';
import { parseIpnsRecordBytes, parseCachedRecord } from './ipns-record.codec';

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

      let publicKeyBytes: Uint8Array | undefined;
      if (dto.publicKey !== undefined) {
        try {
          publicKeyBytes = Uint8Array.from(atob(dto.publicKey), (c) => c.charCodeAt(0));
        } catch {
          throw new BadRequestException('Invalid base64-encoded publicKey');
        }

        if (publicKeyBytes.length !== 32) {
          throw new BadRequestException('publicKey must be a raw 32-byte Ed25519 public key');
        }

        // Verify the public key cryptographically derives to the claimed IPNS name
        const derivedName = await deriveIpnsName(publicKeyBytes);
        if (derivedName !== dto.ipnsName) {
          throw new BadRequestException('publicKey does not correspond to the given ipnsName');
        }
      }

      // Verify the record's Ed25519 SignatureV2 against the key the IPNS name
      // encodes. A validly-signed record proves possession of the private key,
      // which IS the authority to update this name — the cache is keyed by
      // ipnsName, not by user, so any holder of the key may publish.
      if (!(await verifyIpnsRecordSignature(dto.ipnsName, recordBytes))) {
        throw new BadRequestException('IPNS record signature verification failed');
      }

      // Save to DB first so resolve always has a fallback, even if delegated
      // routing fails (e.g. rate-limited, network error, DHT propagation delay).
      const folder = await this.upsertFolderIpns(
        userId,
        dto.ipnsName,
        dto.metadataCid,
        recordBytes,
        publicKeyBytes,
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
    signedRecord: Uint8Array,
    publicKey?: Uint8Array,
    encryptedIpnsPrivateKey?: string,
    keyEpoch?: number,
    recordType: 'folder' | 'file' = 'folder',
    expectedSequenceNumber?: string
  ): Promise<FolderIpns> {
    // The cache is keyed by ipnsName alone — there is one canonical row per name.
    // The caller's authority to update it was already proven by signature
    // verification in publishRecord (key possession), so no ownership/share check
    // is needed here: whoever holds the key updates the canonical record.
    const existing = await this.folderIpnsRepository.findOne({ where: { ipnsName } });

    // Anti-rollback: the incoming record's EMBEDDED sequence (covered by the
    // signature, so tamper-evident) must not regress below the stored record's.
    // Without this, anyone who observes the public IPNS record could replay an
    // old-but-still-valid signed copy (no key needed) to roll the canonical row
    // back to a stale CID — independent of the optional expectedSequenceNumber CAS.
    // Equal sequences are allowed (idempotent re-publish of the current record).
    // incomingParsed is set here when existing?.signedRecord is present (anti-rollback
    // path) so S1 can reuse it below without a second parseIpnsRecord call.
    let incomingParsed: { value: string; sequence: bigint } | null = null;
    if (existing?.signedRecord) {
      const [incoming, stored] = await Promise.all([
        parseIpnsRecord(signedRecord),
        parseIpnsRecord(existing.signedRecord),
      ]);
      if (incoming.sequence < stored.sequence) {
        throw new ConflictException({
          statusCode: 409,
          message: 'IPNS record sequence regression rejected (rollback/replay)',
          currentSequenceNumber: existing.sequenceNumber,
        });
      }
      incomingParsed = incoming;
    }

    // Conflict detection: when expectedSequenceNumber is provided, verify it matches
    // the DB-stored sequence. This is an optimistic concurrency check (CAS) that fires
    // before the S1 embedded-sequence check so that concurrent-modification 409s remain
    // the authoritative signal for stale clients.
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

    // S1 (D-01): embedded-vs-DTO publish-time integrity gate. Runs after the CAS check
    // so that concurrent-modification 409s take priority over tamper-detection 400s.
    // Parse the incoming record exactly once (reuse anti-rollback parse when available).
    if (incomingParsed === null) {
      incomingParsed = await parseIpnsRecord(signedRecord);
    }
    // S1 CID check: the FULL embedded signed-record value must strictly equal
    // `/ipfs/${metadataCid}`. Anchoring the whole value (not just the first CID
    // substring) prevents a record like `/ipfs/<metadataCid>/extra` from passing
    // a substring match while delegated routing publishes a divergent raw value.
    const expectedIpfsValue = `/ipfs/${metadataCid}`;
    if (incomingParsed.value !== expectedIpfsValue) {
      throw new BadRequestException(
        `signedRecord value does not match metadataCid: embedded=${incomingParsed.value}, expected=${expectedIpfsValue}`
      );
    }
    // D-09 (Plan 58-02): unconditional embedded-sequence gate.
    // Runs after the CAS 409 check so concurrent-modification keeps its 409 status.
    // Reuses incomingParsed from the single-parse guard above (never calls parseIpnsRecord twice).
    const embeddedSeq = incomingParsed.sequence; // bigint
    let isIdempotentRepublish = false;
    if (!existing) {
      // First publish: only embedded 1 accepted (D-03 strict — T-58-08, Plan 60-05).
      // Embedded 0 is no longer tolerated; all first-publish producers unified to 1 in Plan 60-02.
      if (embeddedSeq !== 1n) {
        throw new BadRequestException(
          `First publish: embedded sequence must be 1, got ${embeddedSeq}`
        );
      }
    } else {
      const dbSeq = BigInt(existing.sequenceNumber);
      if (embeddedSeq === dbSeq) {
        // Idempotent republish — TEE 6-hour re-sign path (D-09 / Pitfall 4).
        // Do NOT increment the DB sequence, but still update latestCid/signedRecord below.
        isIdempotentRepublish = true;
      } else if (embeddedSeq === dbSeq + 1n) {
        // Normal forward publish — increment allowed.
      } else if (embeddedSeq < dbSeq) {
        throw new BadRequestException(
          `Rollback rejected: embedded sequence ${embeddedSeq} < stored ${dbSeq}`
        );
      } else {
        // embeddedSeq > dbSeq + 1n — wild jump / wedge poison (T-58-10).
        throw new BadRequestException(
          `Sequence jump rejected: embedded ${embeddedSeq}, expected ${dbSeq + 1n}`
        );
      }
    }

    if (existing) {
      if (publicKey && existing.publicKey && !existing.publicKey.equals(Buffer.from(publicKey))) {
        throw new BadRequestException('publicKey does not match the existing IPNS entry');
      }

      // Update existing entry.
      // D-09: skip sequence increment on idempotent republish (TEE re-sign path);
      // still update latestCid and signedRecord (Pitfall 4 — must not skip CID update).
      if (!isIdempotentRepublish) {
        existing.sequenceNumber = (BigInt(existing.sequenceNumber) + 1n).toString();
      }
      existing.latestCid = metadataCid;
      existing.signedRecord = Buffer.from(signedRecord);
      existing.publicKey = publicKey ? Buffer.from(publicKey) : existing.publicKey;
      existing.recordType = recordType;
      existing.updatedAt = new Date();

      // Only update encrypted key if provided (e.g., on key rotation).
      // Guard: only the owner can update TEE enrollment fields — write-share
      // recipients must not overwrite encryptedIpnsPrivateKey or keyEpoch.
      if (encryptedIpnsPrivateKey && keyEpoch !== undefined && existing.userId === userId) {
        existing.encryptedIpnsPrivateKey = Buffer.from(encryptedIpnsPrivateKey, 'hex');
        existing.keyEpoch = keyEpoch;
      }

      const saved = await this.folderIpnsRepository.save(existing);

      // Auto-enroll for TEE republishing when encrypted key is provided.
      // Use existing.userId (the FolderIpns owner) for enrollment, not the
      // authenticated user — a write-share recipient publishes to the owner's record.
      if (encryptedIpnsPrivateKey && keyEpoch !== undefined && existing.userId === userId) {
        this.republishService
          .enrollFolder(
            existing.userId,
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
      signedRecord: Buffer.from(signedRecord),
      publicKey: publicKey ? Buffer.from(publicKey) : null,
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
   * Batch unenroll IPNS names from TEE republishing.
   * Called when files/folders are deleted to prevent orphaned enrollments.
   * Failures for individual names are logged but do not fail the batch.
   */
  async unenrollBatch(userId: string, ipnsNames: string[]): Promise<{ totalUnenrolled: number }> {
    const results = await Promise.allSettled(
      ipnsNames.map((ipnsName) => this.republishService.unenrollIpns(userId, ipnsName))
    );
    let unenrolled = 0;
    for (let i = 0; i < results.length; i++) {
      if (results[i].status === 'fulfilled') {
        unenrolled += (results[i] as PromiseFulfilledResult<number>).value;
      } else {
        const err = (results[i] as PromiseRejectedResult).reason;
        this.logger.warn(
          `Failed to unenroll ${ipnsNames[i]}: ${err instanceof Error ? err.message : err}`
        );
      }
    }
    return { totalUnenrolled: unenrolled };
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
          result = await parseIpnsRecordBytes(recordBytes, this.logger);
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
      const cachedResult = await parseCachedRecord(cached, this.logger);

      if (result && cachedResult) {
        // Both sources available — prefer the one with the higher sequence number.
        // D-06 (Plan 60-05): removed withCachedPublicKey enrich and equal-seq
        // signatureV2 enrich; parseCachedRecord now returns null for null-signedRecord
        // rows, so these branches were unreachable for legacy rows and unnecessary
        // for fresh rows (pubKey is already embedded in the signed record).
        const networkSeq = BigInt(result.sequenceNumber);
        const dbSeq = BigInt(cachedResult.sequenceNumber);
        if (dbSeq > networkSeq) {
          this.logger.log(
            `DB cache has newer sequence (${dbSeq} > ${networkSeq}) for ${ipnsName}, using DB: ${cachedResult.cid}`
          );
          timerSource = 'db';
          source = 'network_stale';
          resolveFound = true;
          return cachedResult;
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
      if (cachedResult) {
        this.logger.log(`Resolved ${ipnsName} from DB cache: ${cachedResult.cid}`);
        timerSource = 'db';
        source = 'db_cache';
        resolveFound = true;
        return cachedResult;
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
}
