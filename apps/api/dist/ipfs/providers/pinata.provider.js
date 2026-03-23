"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PinataProvider = void 0;
const common_1 = require("@nestjs/common");
class PinataProvider {
    pinataJwt;
    pinataBaseUrl = 'https://api.pinata.cloud';
    gatewayBaseUrl = 'https://gateway.pinata.cloud';
    constructor(pinataJwt) {
        this.pinataJwt = pinataJwt;
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
    async pinFile(data, metadata) {
        if (!data || data.length === 0) {
            throw new common_1.BadRequestException('File data cannot be empty');
        }
        // Use native FormData (Node.js 18+) for compatibility with native fetch
        const formData = new FormData();
        // Convert Buffer to ArrayBuffer for Blob compatibility (TypeScript 5.9 strict typing)
        const arrayBuffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
        const blob = new Blob([arrayBuffer], { type: 'application/octet-stream' });
        formData.append('file', blob, `encrypted-${Date.now()}`);
        if (metadata) {
            formData.append('pinataMetadata', JSON.stringify({
                keyvalues: metadata,
            }));
        }
        // Always use CIDv1 for modern IPFS
        formData.append('pinataOptions', JSON.stringify({
            cidVersion: 1,
        }));
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
                throw new common_1.InternalServerErrorException(`Pinata upload failed: ${response.status} - ${errorText}`);
            }
            const result = await response.json();
            return {
                cid: result.IpfsHash,
                size: result.PinSize,
            };
        }
        catch (error) {
            if (error instanceof common_1.BadRequestException || error instanceof common_1.InternalServerErrorException) {
                throw error;
            }
            throw new common_1.InternalServerErrorException(`Failed to pin file to IPFS: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    /**
     * Unpin a file from IPFS via Pinata.
     * @param cid - The CID of the file to unpin
     */
    async unpinFile(cid) {
        if (!cid || typeof cid !== 'string') {
            throw new common_1.BadRequestException('CID is required');
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
                throw new common_1.InternalServerErrorException(`Pinata unpin failed: ${response.status} - ${errorText}`);
            }
        }
        catch (error) {
            if (error instanceof common_1.BadRequestException ||
                error instanceof common_1.InternalServerErrorException ||
                error instanceof common_1.NotFoundException) {
                throw error;
            }
            throw new common_1.InternalServerErrorException(`Failed to unpin file from IPFS: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    /**
     * Get a file from IPFS via Pinata gateway.
     * @param cid - The CID of the file to retrieve
     * @returns The file content as a Buffer
     */
    async getFile(cid) {
        if (!cid || typeof cid !== 'string') {
            throw new common_1.BadRequestException('CID is required');
        }
        try {
            const response = await fetch(`${this.gatewayBaseUrl}/ipfs/${cid}`);
            if (response.status === 404) {
                throw new common_1.NotFoundException(`File not found: ${cid}`);
            }
            if (!response.ok) {
                const errorText = await response.text();
                throw new common_1.InternalServerErrorException(`Pinata fetch failed: ${response.status} - ${errorText}`);
            }
            const arrayBuffer = await response.arrayBuffer();
            return Buffer.from(arrayBuffer);
        }
        catch (error) {
            if (error instanceof common_1.BadRequestException ||
                error instanceof common_1.InternalServerErrorException ||
                error instanceof common_1.NotFoundException) {
                throw error;
            }
            throw new common_1.InternalServerErrorException(`Failed to get file from IPFS: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
}
exports.PinataProvider = PinataProvider;
//# sourceMappingURL=pinata.provider.js.map