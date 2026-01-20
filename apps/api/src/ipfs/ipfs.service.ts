import {
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import FormData from 'form-data';
import { Readable } from 'stream';

interface PinataResponse {
  IpfsHash: string;
  PinSize: number;
  Timestamp: string;
}

@Injectable()
export class IpfsService {
  private readonly pinataJwt: string;
  private readonly pinataBaseUrl = 'https://api.pinata.cloud';

  constructor(private readonly configService: ConfigService) {
    const jwt = this.configService.get<string>('PINATA_JWT');
    if (!jwt) {
      throw new Error('PINATA_JWT environment variable is required');
    }
    this.pinataJwt = jwt;
  }

  /**
   * Pin an encrypted file to IPFS via Pinata.
   * @param data - The encrypted file buffer to pin
   * @param metadata - Optional key-value metadata to attach to the pin
   * @returns The CID and size of the pinned file
   */
  async pinFile(
    data: Buffer,
    metadata?: Record<string, string>
  ): Promise<{ cid: string; size: number }> {
    if (!data || data.length === 0) {
      throw new BadRequestException('File data cannot be empty');
    }

    const formData = new FormData();
    formData.append('file', Readable.from(data), {
      filename: `encrypted-${Date.now()}`,
      contentType: 'application/octet-stream',
    });

    if (metadata) {
      formData.append(
        'pinataMetadata',
        JSON.stringify({
          keyvalues: metadata,
        })
      );
    }

    // Always use CIDv1 for modern IPFS
    formData.append(
      'pinataOptions',
      JSON.stringify({
        cidVersion: 1,
      })
    );

    try {
      const response = await fetch(`${this.pinataBaseUrl}/pinning/pinFileToIPFS`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.pinataJwt}`,
          ...formData.getHeaders(),
        },
        body: formData as unknown as BodyInit,
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new InternalServerErrorException(
          `Pinata upload failed: ${response.status} - ${errorText}`
        );
      }

      const result: PinataResponse = await response.json();
      return {
        cid: result.IpfsHash,
        size: result.PinSize,
      };
    } catch (error) {
      if (error instanceof BadRequestException || error instanceof InternalServerErrorException) {
        throw error;
      }
      throw new InternalServerErrorException(
        `Failed to pin file to IPFS: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Unpin a file from IPFS via Pinata.
   * @param cid - The CID of the file to unpin
   */
  async unpinFile(cid: string): Promise<void> {
    if (!cid || typeof cid !== 'string') {
      throw new BadRequestException('CID is required');
    }

    try {
      const response = await fetch(`${this.pinataBaseUrl}/pinning/unpin/${cid}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${this.pinataJwt}`,
        },
      });

      // 200 = success, 404 = already unpinned (treat as success)
      if (response.status === 404) {
        // Already unpinned, treat as success
        return;
      }

      if (!response.ok) {
        const errorText = await response.text();
        throw new InternalServerErrorException(
          `Pinata unpin failed: ${response.status} - ${errorText}`
        );
      }
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof InternalServerErrorException ||
        error instanceof NotFoundException
      ) {
        throw error;
      }
      throw new InternalServerErrorException(
        `Failed to unpin file from IPFS: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }
}
