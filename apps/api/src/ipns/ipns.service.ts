import { Injectable, HttpException, HttpStatus, BadRequestException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { FolderIpns } from './entities/folder-ipns.entity';
import { PublishIpnsDto, PublishIpnsResponseDto } from './dto';

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

    // Check if this is a new folder (needs encryptedIpnsPrivateKey)
    const existingFolder = await this.getFolderIpns(userId, dto.ipnsName);
    if (!existingFolder && !dto.encryptedIpnsPrivateKey) {
      throw new BadRequestException(
        'encryptedIpnsPrivateKey is required for first publish of a folder'
      );
    }
    if (!existingFolder && dto.keyEpoch === undefined) {
      throw new BadRequestException('keyEpoch is required for first publish of a folder');
    }

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

      return this.folderIpnsRepository.save(existing);
    }

    // Create new entry
    const folder = this.folderIpnsRepository.create({
      userId,
      ipnsName,
      latestCid: metadataCid,
      sequenceNumber: '0',
      encryptedIpnsPrivateKey: Buffer.from(encryptedIpnsPrivateKey!, 'hex'),
      keyEpoch: keyEpoch!,
      isRoot: false, // Root folder is tracked in Vault entity
    });

    return this.folderIpnsRepository.save(folder);
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

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
