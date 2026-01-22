import {
  InternalServerErrorException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { IpfsProvider } from './ipfs-provider.interface';

interface PinataResponse {
  IpfsHash: string;
  PinSize: number;
  Timestamp: string;
}

export class PinataProvider implements IpfsProvider {
  private readonly pinataBaseUrl = 'https://api.pinata.cloud';
  private readonly gatewayBaseUrl = 'https://gateway.pinata.cloud';

  constructor(private readonly pinataJwt: string) {
    if (!pinataJwt) {
      throw new Error('Pinata JWT is required');
    }
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

    // Use native FormData (Node.js 18+) for compatibility with native fetch
    const formData = new FormData();
    // Convert Buffer to ArrayBuffer for Blob compatibility (TypeScript 5.9 strict typing)
    const arrayBuffer = data.buffer.slice(
      data.byteOffset,
      data.byteOffset + data.byteLength
    ) as ArrayBuffer;
    const blob = new Blob([arrayBuffer], { type: 'application/octet-stream' });
    formData.append('file', blob, `encrypted-${Date.now()}`);

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
        },
        body: formData,
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

  /**
   * Get a file from IPFS via Pinata gateway.
   * @param cid - The CID of the file to retrieve
   * @returns The file content as a Buffer
   */
  async getFile(cid: string): Promise<Buffer> {
    if (!cid || typeof cid !== 'string') {
      throw new BadRequestException('CID is required');
    }

    try {
      const response = await fetch(`${this.gatewayBaseUrl}/ipfs/${cid}`);

      if (response.status === 404) {
        throw new NotFoundException(`File not found: ${cid}`);
      }

      if (!response.ok) {
        const errorText = await response.text();
        throw new InternalServerErrorException(
          `Pinata fetch failed: ${response.status} - ${errorText}`
        );
      }

      const arrayBuffer = await response.arrayBuffer();
      return Buffer.from(arrayBuffer);
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof InternalServerErrorException ||
        error instanceof NotFoundException
      ) {
        throw error;
      }
      throw new InternalServerErrorException(
        `Failed to get file from IPFS: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }
}
