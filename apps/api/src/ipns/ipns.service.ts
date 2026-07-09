import {
  Injectable,
  HttpException,
  HttpStatus,
  BadRequestException,
  ConflictException,
  NotFoundException,
  Logger,
  Inject,
  forwardRef,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { IpnsRecord } from './entities/ipns-record.entity';
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
import {
  deriveIpnsName,
  parseIpnsRecord,
  publicKeyFromIpnsName,
  verifyIpnsRecordSignature,
} from '@cipherbox/crypto';
import { parseIpnsRecordBytes, parseCachedRecord, type SeqFloor } from './ipns-record.codec';
import { ipnsVerifyCache } from './ipns-verify-cache';

@Injectable()
export class IpnsService {
  private readonly logger = new Logger(IpnsService.name);

  constructor(
    @InjectRepository(IpnsRecord)
    private readonly ipnsRecordRepository: Repository<IpnsRecord>,
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
    dto: PublishIpnsDto | PublishIpnsEntryDto
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
      //
      // D-11 short-circuit: if this exact (ipnsName, recordBytes) combination was
      // already verified by THIS server within the cache TTL, skip the redundant
      // Ed25519 call. The cache key is `ipnsName:base64(recordBytes)` — the record
      // bytes uniquely identify the (ipnsName, sequenceNumber, signatureV2) triple
      // since any change to signatureV2, seq, or CID produces different bytes.
      // The cache is ONLY populated from successful in-process verifications — never
      // from the resolve path or DHT records (T-60-20/T-60-21/D-11 invariant).
      const recordBytesBase64 = Buffer.from(recordBytes).toString('base64');
      const cacheHit = ipnsVerifyCache.isVerified(dto.ipnsName, '', recordBytesBase64);

      if (!cacheHit) {
        if (!(await verifyIpnsRecordSignature(dto.ipnsName, recordBytes))) {
          throw new BadRequestException('IPNS record signature verification failed');
        }
        // Record in cache only after a successful in-process verify.
        ipnsVerifyCache.recordVerified(dto.ipnsName, '', recordBytesBase64);
      }

      // Save to DB first so resolve always has a fallback, even if delegated
      // routing fails (e.g. rate-limited, network error, DHT propagation delay).
      const folder = await this.upsertIpnsRecord(
        userId,
        dto.ipnsName,
        dto.metadataCid,
        recordBytes,
        dto.encryptedIpnsPrivateKey,
        dto.keyEpoch,
        dto.expectedSequenceNumber,
        dto.generation
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
        batch.map((entry) => this.publishRecord(userId, entry))
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
          // A tombstoned name (410 GONE) is permanently retired and can never publish
          // again. Surface it by failing the batch instead of masking it as a transient
          // per-record failure ({ success: false, sequenceNumber: '0' }) — otherwise a
          // client retry loop or TEE rotation batch would re-attempt a dead name forever.
          // Mirrors the ConflictException treatment above.
          if (reason instanceof HttpException && reason.getStatus() === HttpStatus.GONE) {
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
   *
   * First-publish: INSERT with sequence_number=1, generation=0 (unchanged).
   * Forward-publish: ONE atomic conditional UPDATE with fused seq CAS, generation gate,
   * and tombstone gate — no TOCTOU (D-03/TEE-04/TEE-07).
   */
  private async upsertIpnsRecord(
    userId: string,
    ipnsName: string,
    metadataCid: string,
    signedRecord: Uint8Array,
    encryptedIpnsPrivateKey?: string,
    keyEpoch?: number,
    expectedSequenceNumber?: string,
    generation?: string
  ): Promise<IpnsRecord> {
    // The cache is keyed by ipnsName alone — there is one canonical row per name.
    // The caller's authority to update it was already proven by signature
    // verification in publishRecord (key possession), so no ownership/share check
    // is needed here: whoever holds the key updates the canonical record.
    const existing = await this.ipnsRecordRepository.findOne({ where: { ipnsName } });

    // Tombstone is terminal: once a name is retired, every subsequent publish
    // (stale or forward) must fail closed with 410. Short-circuit here, before the
    // anti-rollback / embedded-sequence gates below, which would otherwise mask a
    // tombstoned row as a 400/409 for a stale incoming record (the CAS tombstone
    // gate only runs for the forward-update path).
    if (existing?.tombstonedAt) {
      throw new HttpException({ error: 'IPNS_TOMBSTONED', ipnsName }, HttpStatus.GONE);
    }

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

    // S1 (D-01): embedded-vs-DTO publish-time integrity gate.
    // Parse the incoming record exactly once (reuse anti-rollback parse when available).
    if (incomingParsed === null) {
      incomingParsed = await parseIpnsRecord(signedRecord);
    }
    // TypeScript narrowing: incomingParsed is guaranteed non-null here — either set in the
    // anti-rollback path above (existing?.signedRecord branch) or assigned just above.
    const resolvedParsed = incomingParsed;
    // S1 CID check: the FULL embedded signed-record value must strictly equal
    // `/ipfs/${metadataCid}`. Anchoring the whole value (not just the first CID
    // substring) prevents a record like `/ipfs/<metadataCid>/extra` from passing
    // a substring match while delegated routing publishes a divergent raw value.
    const expectedIpfsValue = `/ipfs/${metadataCid}`;
    if (resolvedParsed.value !== expectedIpfsValue) {
      throw new BadRequestException(
        `signedRecord value does not match metadataCid: embedded=${resolvedParsed.value}, expected=${expectedIpfsValue}`
      );
    }
    // D-09 (Plan 58-02): unconditional embedded-sequence gate.
    // Reuses resolvedParsed from the single-parse guard above (never calls parseIpnsRecord twice).
    const embeddedSeq = resolvedParsed.sequence; // bigint
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
        // latestCid is preserved ONLY for a genuine same-CID idempotent retry;
        // a republish at the same sequence carrying a DIFFERENT CID is
        // equivocation (D-05) and is rejected below, never silently applied.
        // The TEE lease-renewer (republish.service.ts renewIpnsRecordEol) never
        // reaches this branch — it performs a standalone UPDATE that re-signs
        // the existing CID/seq in place and never calls upsertIpnsRecord, so
        // this guard can only be hit by a fresh, externally-signed publish.
        if (metadataCid !== existing.latestCid) {
          throw new BadRequestException(
            `Same-sequence republish with a different CID rejected (equivocation): stored=${existing.latestCid}, incoming=${metadataCid}, sequence=${dbSeq}`
          );
        }
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
      // D-03 / TEE-04 / TEE-07: ONE atomic conditional UPDATE that fuses:
      //   - sequence CAS (sequence_number = :expected)
      //   - forward-only generation gate (generation <= CAST(:incoming AS bigint))
      //   - tombstone gate (tombstoned_at IS NULL)
      // No in-memory CAS comparison gates the write; result.affected drives the outcome.

      // Guard: only the owner can update TEE enrollment fields — write-share
      // recipients must not overwrite encryptedIpnsPrivateKey or keyEpoch.
      const shouldUpdateKey = !!(
        encryptedIpnsPrivateKey &&
        keyEpoch !== undefined &&
        existing.userId === userId
      );

      // Build SET clause conditionally (TypeORM-safe approach).
      // sequenceNumber uses raw SQL so TypeORM doesn't double-encode it.
      type CasSetClause = {
        latestCid: string;
        signedRecord: Buffer;
        sequenceNumber: () => string;
        updatedAt: Date;
        generation?: string;
        encryptedIpnsPrivateKey?: Buffer;
        keyEpoch?: number;
      };
      const setClause: CasSetClause = {
        latestCid: metadataCid,
        signedRecord: Buffer.from(signedRecord),
        // D-09: idempotent republish keeps sequence_number unchanged
        sequenceNumber: () => (isIdempotentRepublish ? 'sequence_number' : 'sequence_number + 1'),
        updatedAt: new Date(),
      };
      // Only update generation when explicitly provided (undefined = no-op, preserve stored value)
      if (generation !== undefined) {
        setClause.generation = generation;
      }
      if (shouldUpdateKey) {
        setClause.encryptedIpnsPrivateKey = Buffer.from(encryptedIpnsPrivateKey!, 'hex');
        setClause.keyEpoch = keyEpoch!;
      }

      // When generation is not provided, default to the stored generation so the
      // WHERE gate is a no-op (generation <= existing.generation → always true).
      const effectiveIncomingGeneration = generation ?? existing.generation;
      // When expectedSequenceNumber is not provided, default to the stored sequence
      // so the seq CAS passes for the current row (backward-compat unconditional publish).
      const effectiveExpected = expectedSequenceNumber ?? existing.sequenceNumber;

      const updateResult = await this.ipnsRecordRepository
        .createQueryBuilder()
        .update(IpnsRecord)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .set(setClause as any)
        .where(
          'ipns_name = :ipnsName AND sequence_number = :expected AND generation <= CAST(:incoming AS bigint) AND tombstoned_at IS NULL',
          {
            ipnsName,
            expected: effectiveExpected,
            incoming: effectiveIncomingGeneration,
          }
        )
        .execute();

      if (updateResult.affected === 0) {
        // Single follow-up read to distinguish 409 (stale seq / generation regression)
        // from 410 (record tombstoned). D-03: exactly one follow-up read.
        const row = await this.ipnsRecordRepository.findOne({ where: { ipnsName } });
        if (!row) {
          throw new NotFoundException(`IPNS record not found: ${ipnsName}`);
        }
        if (row.tombstonedAt) {
          throw new HttpException({ error: 'IPNS_TOMBSTONED', ipnsName }, HttpStatus.GONE);
        }
        throw new ConflictException({
          statusCode: 409,
          message: 'Sequence number mismatch or generation regression',
          currentSequenceNumber: row.sequenceNumber,
        });
      }

      // Compute the new sequence number for TEE enrollment and return.
      // No follow-up findOne needed: affected===1 means the CAS succeeded.
      const newSeq = isIdempotentRepublish
        ? existing.sequenceNumber
        : (BigInt(existing.sequenceNumber) + 1n).toString();

      // Auto-enroll for TEE republishing when encrypted key is provided.
      // Use existing.userId (the IpnsRecord owner) for enrollment, not the
      // authenticated user — a write-share recipient publishes to the owner's record.
      // enrollFolder is scheduling-only (2 args): signing columns live in ipns_records.
      if (shouldUpdateKey) {
        this.republishService
          .enrollFolder(existing.userId, ipnsName)
          .catch((err) =>
            this.logger.warn(
              `Failed to enroll ${ipnsName} for republishing: ${err instanceof Error ? err.message : String(err)}`
            )
          );
      }

      return { ...existing, sequenceNumber: newSeq, latestCid: metadataCid } as IpnsRecord;
    }

    // Create new entry — sequence starts at '1' to match the IPNS record
    // the client signed (clients compute newSeq = 0n + 1n = 1n for first publish).
    const folder = this.ipnsRecordRepository.create({
      userId,
      ipnsName,
      latestCid: metadataCid,
      sequenceNumber: '1',
      signedRecord: Buffer.from(signedRecord),
      encryptedIpnsPrivateKey: encryptedIpnsPrivateKey
        ? Buffer.from(encryptedIpnsPrivateKey, 'hex')
        : null,
      keyEpoch: keyEpoch ?? null,
      // Persist the incoming generation on first publish so the forward-only
      // generation gate is anchored at the client's intended value. Defaulting to
      // the stored 0 here would let later, lower generations pass the gate.
      generation: generation ?? '0',
      isRoot: false, // Root folder is tracked in Vault entity
    });

    // D-06: two brand-new publishRecord calls for the same ipnsName can race
    // past the findOne(null) check above and both attempt this INSERT; the
    // loser hits the DB's unique constraint on ipns_name. Translate that
    // Postgres unique-violation (23505) into a clean, idempotent-retriable
    // 409 instead of letting an ambiguous 500 surface. Mirrors the
    // err.code / err.driverError.code idiom used in shares.service.ts —
    // never QueryFailedError instanceof, which does not survive the
    // TypeORM driver boundary reliably.
    let saved: IpnsRecord;
    try {
      saved = await this.ipnsRecordRepository.save(folder);
    } catch (err: unknown) {
      const code = (err as { code?: string; driverError?: { code?: string } }).code;
      const driverCode = (err as { driverError?: { code?: string } }).driverError?.code;
      if (code === '23505' || driverCode === '23505') {
        throw new ConflictException({ statusCode: 409, message: 'IPNS record already exists' });
      }
      throw err;
    }

    // Auto-enroll for TEE republishing when encrypted key is provided.
    // enrollFolder is scheduling-only (2 args): signing columns live in ipns_records.
    if (encryptedIpnsPrivateKey && keyEpoch !== undefined) {
      this.republishService
        .enrollFolder(userId, ipnsName)
        .catch((err) =>
          this.logger.warn(
            `Failed to enroll ${ipnsName} for republishing: ${err instanceof Error ? err.message : String(err)}`
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
   * Get an IPNS record by user and IPNS name
   */
  async getIpnsRecord(userId: string, ipnsName: string): Promise<IpnsRecord | null> {
    return this.ipnsRecordRepository.findOne({
      where: { userId, ipnsName },
    });
  }

  /**
   * Get all IPNS records for a user (for TEE republishing)
   */
  async getAllIpnsRecords(userId: string): Promise<IpnsRecord[]> {
    return this.ipnsRecordRepository.find({
      where: { userId },
      order: { createdAt: 'ASC' },
    });
  }

  /**
   * Tombstone an IPNS record owned by userId.
   *
   * Sets tombstoned_at = NOW() atomically, then removes the name from the
   * TEE republish schedule. Subsequent publish attempts return HTTP 410 GONE
   * via the unified CAS WHERE (tombstoned_at IS NULL). Subsequent resolves
   * also return 410 (checked in resolveRecord before parseCachedRecord).
   *
   * V4 access control: tombstone is scoped to the owner (user_id = :userId).
   * Write-share recipients cannot tombstone a record they do not own.
   */
  async tombstoneRecord(userId: string, ipnsName: string): Promise<void> {
    const result = await this.ipnsRecordRepository
      .createQueryBuilder()
      .update(IpnsRecord)
      .set({ tombstonedAt: new Date() })
      .where('ipns_name = :ipnsName AND tombstoned_at IS NULL AND user_id = :userId', {
        ipnsName,
        userId,
      })
      .execute();

    if (result.affected === 0) {
      // affected === 0 is ambiguous: the row is either already tombstoned
      // (idempotent success) or it does not exist / is not owned by the caller.
      // Distinguish with an owner-scoped lookup so a mistyped or unowned name
      // returns 404 instead of a misleading 200; an already-tombstoned row is a
      // no-op success.
      const owned = await this.ipnsRecordRepository.findOne({ where: { ipnsName, userId } });
      if (!owned) {
        throw new NotFoundException(`IPNS record not found: ${ipnsName}`);
      }
    }

    // Unenroll from TEE republish schedule regardless of whether the UPDATE matched
    // (idempotent: if already unenrolled, unenrollIpns returns 0 affected).
    await this.republishService.unenrollIpns(userId, ipnsName);
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
          // Ed25519 identity records omit the embedded pubKey (the name encodes the key —
          // see parse-record.ts), so a network-resolved record carries signatureV2/data but
          // no pubKey. The strict client and the controller's all-or-nothing signature bundle
          // need pubKey to verify, so supplement it from the requested name — the same trust
          // model the DB-cached path uses (ipns-record.codec.ts), since the name cryptographically
          // commits to the key. This makes the §6.5 seqFloor shared-folder serve path (and any
          // network-ahead serve) client-verifiable instead of failing closed.
          if (result && result.signatureV2 && result.data && !result.pubKey) {
            try {
              result.pubKey = Buffer.from(publicKeyFromIpnsName(ipnsName)).toString('base64');
            } catch (e) {
              this.logger.warn(
                `Could not recover pubKey from name ${ipnsName} for network record: ${
                  e instanceof Error ? e.message : String(e)
                }`
              );
              // Fail closed: a network record we cannot make client-verifiable (no
              // recoverable pubKey for the all-or-nothing signature bundle) must not be
              // served as an unverifiable CID. Discard it and fall back to DB cache / 404.
              result = null;
            }
          }
          if (result) {
            this.logger.debug(`IPNS name resolved successfully: ${ipnsName} -> ${result.cid}`);
          }
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
      const cached = await this.ipnsRecordRepository.findOne({
        where: { ipnsName },
      });

      // D-07: tombstoned name returns 410 before serving any cached or network CID.
      // Checked here so both DB-only and network+DB paths are covered.
      if (cached?.tombstonedAt) {
        throw new HttpException({ error: 'IPNS_TOMBSTONED', ipnsName }, HttpStatus.GONE);
      }

      const cachedResult = await parseCachedRecord(cached, this.logger);

      // TEE-05 / §6.5: type-narrow cachedResult into the three-way discriminated union.
      //
      //  seqFloor discriminant → shared-folder row with no signedRecord.
      //    Network record must have networkSeq >= seqFloor to be served.
      //    If network record is below the floor (or absent), fail closed (→ 404).
      //    Never serve a network record ungated when we have a known seq floor.
      //
      //  IpnsRecordFields → normal row: prefer DB when dbSeq >= networkSeq.
      //
      //  null → no cached row or CID mismatch: fall through to network-only (or 404).
      const isSeqFloor = (r: typeof cachedResult): r is SeqFloor => r !== null && 'seqFloor' in r;

      if (isSeqFloor(cachedResult)) {
        // Shared-folder row: gate the network record against the stored seq floor.
        if (result) {
          const networkSeq = BigInt(result.sequenceNumber);
          const floorSeq = BigInt(cachedResult.seqFloor);
          if (networkSeq >= floorSeq) {
            this.logger.debug(
              `seqFloor gate passed for ${ipnsName}: networkSeq=${networkSeq} >= floor=${floorSeq}`
            );
            timerSource = 'network';
            resolveFound = true;
            return result;
          }
          // Network record below floor — fail closed to prevent ungated serve.
          this.logger.warn(
            `seqFloor gate REJECTED for ${ipnsName}: networkSeq=${networkSeq} < floor=${floorSeq} — failing closed`
          );
          return null;
        }
        // No network record and only a seqFloor discriminant — cannot serve.
        return null;
      }

      if (result && cachedResult) {
        // Both sources available. The DB-cached record is the authoritative, fully-signed
        // record the owner published — parseCachedRecord returns it complete, including the
        // pubKey (recovered from the k51 ipnsName via publicKeyFromIpnsName). The network record parsed
        // from delegated routing does NOT carry the signature fields a strict client needs
        // to verify, so prefer the DB record whenever it is at the same or a higher
        // sequence; only defer to the network record when it is strictly ahead (a newer
        // publish not yet in this DB). This restores the resolve-verifiability that Plan
        // 60-05's enrich removal dropped — the strict client re-checks pubKey→name binding
        // and the Ed25519 signature regardless.
        const networkSeq = BigInt(result.sequenceNumber);
        const dbSeq = BigInt(cachedResult.sequenceNumber);
        if (dbSeq >= networkSeq) {
          if (dbSeq > networkSeq) {
            this.logger.log(
              `DB cache has newer sequence (${dbSeq} > ${networkSeq}) for ${ipnsName}, using DB: ${cachedResult.cid}`
            );
            source = 'network_stale';
          } else {
            source = 'db_cache';
          }
          timerSource = 'db';
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
