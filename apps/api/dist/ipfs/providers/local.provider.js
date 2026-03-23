"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LocalProvider = void 0;
const common_1 = require("@nestjs/common");
class LocalProvider {
    apiUrl;
    constructor(apiUrl, 
    // Gateway URL kept for future use (e.g., public read access)
    // Currently using API directly via cat endpoint
    _gatewayUrl) {
        this.apiUrl = apiUrl;
        if (!apiUrl) {
            throw new Error('IPFS API URL is required');
        }
    }
    /**
     * Pin a file to local IPFS node via Kubo API.
     * @param data - The file buffer to pin
     * @param metadata - Optional metadata (ignored for local IPFS)
     * @returns The CID and size of the pinned file
     */
    async pinFile(data, _metadata) {
        if (!data || data.length === 0) {
            throw new common_1.BadRequestException('File data cannot be empty');
        }
        // Use native FormData (available in Node.js 18+) with Blob for compatibility with native fetch
        const formData = new FormData();
        // Create Blob from Buffer using explicit Uint8Array conversion for type safety
        const blob = new Blob([new Uint8Array(data)], { type: 'application/octet-stream' });
        formData.append('file', blob, `file-${Date.now()}`);
        try {
            // Kubo API uses POST for all operations
            // pin=true ensures the file is pinned, cid-version=1 for CIDv1
            const response = await fetch(`${this.apiUrl}/api/v0/add?pin=true&cid-version=1`, {
                method: 'POST',
                body: formData,
            });
            if (!response.ok) {
                const errorText = await response.text();
                throw new common_1.InternalServerErrorException(`IPFS add failed: ${response.status} - ${errorText}`);
            }
            const result = await response.json();
            return {
                cid: result.Hash,
                size: parseInt(result.Size, 10),
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
     * Unpin a file from local IPFS node.
     * @param cid - The CID of the file to unpin
     */
    async unpinFile(cid) {
        if (!cid || typeof cid !== 'string') {
            throw new common_1.BadRequestException('CID is required');
        }
        try {
            // Kubo API uses POST for all operations including unpin
            const response = await fetch(`${this.apiUrl}/api/v0/pin/rm?arg=${cid}`, {
                method: 'POST',
            });
            if (!response.ok) {
                const errorText = await response.text();
                // "not pinned" means already unpinned - treat as success (idempotent)
                if (errorText.includes('not pinned')) {
                    return;
                }
                throw new common_1.InternalServerErrorException(`IPFS unpin failed: ${response.status} - ${errorText}`);
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
     * Get a file from local IPFS node via Kubo API.
     * @param cid - The CID of the file to retrieve
     * @returns The file content as a Buffer
     */
    async getFile(cid) {
        if (!cid || typeof cid !== 'string') {
            throw new common_1.BadRequestException('CID is required');
        }
        try {
            // Kubo API uses POST for cat operation
            const response = await fetch(`${this.apiUrl}/api/v0/cat?arg=${cid}`, {
                method: 'POST',
            });
            if (!response.ok) {
                const errorText = await response.text();
                // Check for not found errors
                if (errorText.includes('not found') ||
                    errorText.includes('no link') ||
                    errorText.includes('blockstore: block not found')) {
                    throw new common_1.NotFoundException(`File not found: ${cid}`);
                }
                throw new common_1.InternalServerErrorException(`IPFS cat failed: ${response.status} - ${errorText}`);
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
exports.LocalProvider = LocalProvider;
//# sourceMappingURL=local.provider.js.map