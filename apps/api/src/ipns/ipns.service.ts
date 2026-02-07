import { Injectable, HttpException, HttpStatus, BadRequestException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { FolderIpns } from './entities/folder-ipns.entity';
import { PublishIpnsDto, PublishIpnsResponseDto } from './dto';

// Dynamic import for ESM-only ipns package (loaded at runtime)
type UnmarshalIPNSRecord = (bytes: Uint8Array) => { value: string; sequence: bigint };
let unmarshalIPNSRecord: UnmarshalIPNSRecord | null = null;

@Injectable()
export class IpnsService {
  private readonly logger = new Logger(IpnsService.name);
  private readonly delegatedRoutingUrl: string;
  private readonly maxRetries = 3;
  private readonly baseDelayMs = 1000;

  constructor(
    @InjectRepository(FolderIpns)
    private readonly folderIpnsRepository: Repository<FolderIpns>,
    private readonly configService: ConfigService
  ) {
    this.delegatedRoutingUrl = this.configService.get<string>(
      'DELEGATED_ROUTING_URL',
      'https://delegated-ipfs.dev'
    );
  }

  /**
   * Publish a pre-signed IPNS record to the IPFS network via delegated routing
   * and track the folder in the database for TEE republishing
   */
  async publishRecord(userId: string, dto: PublishIpnsDto): Promise<PublishIpnsResponseDto> {
    // Validate base64 record
    let recordBytes: Uint8Array;
    try {
      recordBytes = Uint8Array.from(atob(dto.record), (c) => c.charCodeAt(0));
    } catch {
      throw new BadRequestException('Invalid base64-encoded record');
    }

    // Note: TEE fields (encryptedIpnsPrivateKey, keyEpoch) are optional for Phase 6
    // They will be required when TEE republishing is implemented (Phase 7+)
    // For now, allow publishing without them - the folder will be created/updated
    // via upsert and TEE fields can be added later when the client supports it

    // Publish to delegated routing API with retries
    await this.publishToDelegatedRouting(dto.ipnsName, recordBytes);

    // Update or create folder tracking
    const folder = await this.upsertFolderIpns(
      userId,
      dto.ipnsName,
      dto.metadataCid,
      dto.encryptedIpnsPrivateKey,
      dto.keyEpoch
    );

    return {
      success: true,
      ipnsName: dto.ipnsName,
      sequenceNumber: folder.sequenceNumber,
    };
  }

  /**
   * Publish record to delegated routing API with exponential backoff retry
   */
  private async publishToDelegatedRouting(
    ipnsName: string,
    recordBytes: Uint8Array
  ): Promise<void> {
    const url = `${this.delegatedRoutingUrl}/routing/v1/ipns/${ipnsName}`;

    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        const response = await fetch(url, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/vnd.ipfs.ipns-record',
          },
          body: recordBytes as unknown as BodyInit,
        });

        if (response.ok) {
          this.logger.log(`IPNS record published successfully for ${ipnsName}`);
          return;
        }

        // Handle rate limiting
        if (response.status === 429) {
          const retryAfter = response.headers.get('Retry-After');
          const delayMs = retryAfter
            ? parseInt(retryAfter, 10) * 1000
            : this.baseDelayMs * Math.pow(2, attempt);

          this.logger.warn(`Rate limited on IPNS publish, retrying in ${delayMs}ms`);
          await this.delay(delayMs);
          continue;
        }

        // Non-retryable error
        // [SECURITY: MEDIUM-11] Log full error details but don't expose to client
        const errorText = await response.text();
        this.logger.error(
          `Delegated routing returned ${response.status} for ${ipnsName}: ${errorText}`
        );
        throw new Error(`Delegated routing returned ${response.status}`);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        // Only retry on network errors, not on HTTP errors
        if (
          lastError.message.includes('Delegated routing returned') &&
          !lastError.message.includes('429')
        ) {
          // [SECURITY: MEDIUM-11] Generic error message to avoid leaking internal details
          throw new HttpException(
            'Failed to publish IPNS record to routing network',
            HttpStatus.BAD_GATEWAY
          );
        }

        // Exponential backoff for network errors
        if (attempt < this.maxRetries - 1) {
          const delayMs = this.baseDelayMs * Math.pow(2, attempt);
          this.logger.warn(
            `IPNS publish attempt ${attempt + 1} failed, retrying in ${delayMs}ms: ${lastError.message}`
          );
          await this.delay(delayMs);
        }
      }
    }

    // [SECURITY: MEDIUM-11] Log full error, return generic message
    this.logger.error(
      `Failed to publish IPNS record after ${this.maxRetries} attempts: ${lastError?.message}`
    );
    throw new HttpException(
      'Failed to publish IPNS record to routing network after multiple attempts',
      HttpStatus.BAD_GATEWAY
    );
  }

  /**
   * Create or update a folder IPNS entry
   */
  private async upsertFolderIpns(
    userId: string,
    ipnsName: string,
    metadataCid: string,
    encryptedIpnsPrivateKey?: string,
    keyEpoch?: number
  ): Promise<FolderIpns> {
    const existing = await this.getFolderIpns(userId, ipnsName);

    if (existing) {
      // Update existing entry
      existing.latestCid = metadataCid;
      existing.sequenceNumber = (BigInt(existing.sequenceNumber) + 1n).toString();
      existing.updatedAt = new Date();

      // Only update encrypted key if provided (e.g., on key rotation)
      if (encryptedIpnsPrivateKey && keyEpoch !== undefined) {
        existing.encryptedIpnsPrivateKey = Buffer.from(encryptedIpnsPrivateKey, 'hex');
        existing.keyEpoch = keyEpoch;
      }

      const saved = await this.folderIpnsRepository.save(existing);

      // Auto-enroll for TEE republishing when encrypted key is provided
      // TODO: Wire to RepublishService.enrollFolder when 08-02 creates the republish module
      if (encryptedIpnsPrivateKey && keyEpoch !== undefined) {
        this.logger.log(
          `Folder ${ipnsName} has TEE-encrypted key (epoch ${keyEpoch}), ready for republish enrollment`
        );
      }

      return saved;
    }

    // Create new entry
    const folder = this.folderIpnsRepository.create({
      userId,
      ipnsName,
      latestCid: metadataCid,
      sequenceNumber: '0',
      encryptedIpnsPrivateKey: encryptedIpnsPrivateKey
        ? Buffer.from(encryptedIpnsPrivateKey, 'hex')
        : null,
      keyEpoch: keyEpoch ?? null,
      isRoot: false, // Root folder is tracked in Vault entity
    });

    const saved = await this.folderIpnsRepository.save(folder);

    // Auto-enroll for TEE republishing when encrypted key is provided
    // TODO: Wire to RepublishService.enrollFolder when 08-02 creates the republish module
    if (encryptedIpnsPrivateKey && keyEpoch !== undefined) {
      this.logger.log(
        `New folder ${ipnsName} has TEE-encrypted key (epoch ${keyEpoch}), ready for republish enrollment`
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
   * falling back to the DB-cached CID when delegated routing is unavailable.
   * Returns null if the IPNS name is not found (404)
   */
  async resolveRecord(ipnsName: string): Promise<{ cid: string; sequenceNumber: string } | null> {
    try {
      return await this.resolveFromDelegatedRouting(ipnsName);
    } catch (error) {
      // Only fall back to DB cache on BAD_GATEWAY (delegated routing failures)
      if (error instanceof HttpException && error.getStatus() === HttpStatus.BAD_GATEWAY) {
        this.logger.warn(`Delegated routing failed for ${ipnsName}, falling back to DB cache`);
        const cached = await this.folderIpnsRepository.findOne({
          where: { ipnsName },
        });
        if (cached?.latestCid) {
          this.logger.log(`Resolved ${ipnsName} from DB cache: ${cached.latestCid}`);
          return { cid: cached.latestCid, sequenceNumber: cached.sequenceNumber };
        }
        this.logger.warn(`No DB cache available for ${ipnsName}, re-throwing`);
      }
      throw error;
    }
  }

  /**
   * Resolve an IPNS name via the delegated routing API with retries.
   * Returns null if the IPNS name is not found (404).
   * Throws HttpException (BAD_GATEWAY) on routing failures.
   */
  private async resolveFromDelegatedRouting(
    ipnsName: string
  ): Promise<{ cid: string; sequenceNumber: string } | null> {
    const url = `${this.delegatedRoutingUrl}/routing/v1/ipns/${ipnsName}`;

    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        const response = await fetch(url, {
          method: 'GET',
          headers: {
            Accept: 'application/vnd.ipfs.ipns-record',
          },
        });

        // 404 means IPNS name not found - not an error
        if (response.status === 404) {
          this.logger.debug(`IPNS name not found: ${ipnsName}`);
          return null;
        }

        if (response.ok) {
          // The delegated routing API returns the raw IPNS record
          // We need to parse it to extract the CID and sequence number
          const recordBytes = new Uint8Array(await response.arrayBuffer());
          const parsed = await this.parseIpnsRecord(recordBytes);

          this.logger.debug(`IPNS name resolved successfully: ${ipnsName} -> ${parsed.cid}`);
          return parsed;
        }

        // Handle rate limiting
        if (response.status === 429) {
          const retryAfter = response.headers.get('Retry-After');
          const delayMs = retryAfter
            ? parseInt(retryAfter, 10) * 1000
            : this.baseDelayMs * Math.pow(2, attempt);

          this.logger.warn(`Rate limited on IPNS resolve, retrying in ${delayMs}ms`);
          await this.delay(delayMs);
          continue;
        }

        // Non-retryable error
        // [SECURITY: MEDIUM-11] Log full error details but don't expose to client
        const errorText = await response.text();
        this.logger.error(
          `Delegated routing resolution returned ${response.status} for ${ipnsName}: ${errorText}`
        );
        throw new Error(`Delegated routing returned ${response.status}`);
      } catch (error) {
        // Re-throw HttpException immediately (e.g., parsing errors) - don't retry
        if (error instanceof HttpException) {
          throw error;
        }

        lastError = error instanceof Error ? error : new Error(String(error));

        // Only retry on network errors, not on HTTP errors
        if (
          lastError.message.includes('Delegated routing returned') &&
          !lastError.message.includes('429')
        ) {
          // [SECURITY: MEDIUM-11] Generic error message to avoid leaking internal details
          throw new HttpException(
            'Failed to resolve IPNS name from routing network',
            HttpStatus.BAD_GATEWAY
          );
        }

        // Exponential backoff for network errors
        if (attempt < this.maxRetries - 1) {
          const delayMs = this.baseDelayMs * Math.pow(2, attempt);
          this.logger.warn(
            `IPNS resolve attempt ${attempt + 1} failed, retrying in ${delayMs}ms: ${lastError.message}`
          );
          await this.delay(delayMs);
        }
      }
    }

    // [SECURITY: MEDIUM-11] Log full error, return generic message
    this.logger.error(
      `Failed to resolve IPNS name after ${this.maxRetries} attempts: ${lastError?.message}`
    );
    throw new HttpException(
      'Failed to resolve IPNS name from routing network after multiple attempts',
      HttpStatus.BAD_GATEWAY
    );
  }

  /**
   * Parse an IPNS record to extract CID and sequence number
   * Uses the ipns package to properly deserialize protobuf-encoded records
   */
  private async parseIpnsRecord(
    recordBytes: Uint8Array
  ): Promise<{ cid: string; sequenceNumber: string }> {
    try {
      // Dynamically load ESM-only ipns package at runtime
      if (!unmarshalIPNSRecord) {
        const ipnsModule = await import('ipns');
        unmarshalIPNSRecord = ipnsModule.unmarshalIPNSRecord;
      }

      const record = unmarshalIPNSRecord(recordBytes);

      // Extract CID from the Value field (format: /ipfs/<cid>)
      // The ipns package returns value as a string path (e.g., "/ipfs/bafy...")
      const valuePath = record.value;
      const cidMatch = valuePath.match(/\/ipfs\/([a-zA-Z0-9]+)/);
      if (!cidMatch) {
        this.logger.error('Failed to extract CID from IPNS record value');
        throw new HttpException('Invalid IPNS record format', HttpStatus.BAD_GATEWAY);
      }

      const cid = cidMatch[1];
      // Sequence is a bigint in the record structure
      const sequenceNumber = String(record.sequence ?? 0n);

      this.logger.debug(`Parsed IPNS record: cid=${cid}, sequenceNumber=${sequenceNumber}`);
      return { cid, sequenceNumber };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      this.logger.error(`Failed to parse IPNS record: ${error}`);
      throw new HttpException('Invalid IPNS record format', HttpStatus.BAD_GATEWAY);
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
