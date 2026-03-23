"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var IpnsService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.IpnsService = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const typeorm_2 = require("typeorm");
const config_1 = require("@nestjs/config");
const folder_ipns_entity_1 = require("./entities/folder-ipns.entity");
const republish_service_1 = require("../republish/republish.service");
const ipns_record_parser_1 = require("./ipns-record-parser");
let IpnsService = IpnsService_1 = class IpnsService {
    folderIpnsRepository;
    configService;
    republishService;
    logger = new common_1.Logger(IpnsService_1.name);
    delegatedRoutingUrl;
    maxRetries = 3;
    baseDelayMs = 1000;
    constructor(folderIpnsRepository, configService, republishService) {
        this.folderIpnsRepository = folderIpnsRepository;
        this.configService = configService;
        this.republishService = republishService;
        this.delegatedRoutingUrl = this.configService.get('DELEGATED_ROUTING_URL', 'https://delegated-ipfs.dev');
    }
    /**
     * Publish a pre-signed IPNS record to the IPFS network via delegated routing
     * and track the folder in the database for TEE republishing
     */
    async publishRecord(userId, dto) {
        // Validate base64 record
        let recordBytes;
        try {
            recordBytes = Uint8Array.from(atob(dto.record), (c) => c.charCodeAt(0));
        }
        catch {
            throw new common_1.BadRequestException('Invalid base64-encoded record');
        }
        // Note: TEE fields (encryptedIpnsPrivateKey, keyEpoch) are optional for Phase 6
        // They will be required when TEE republishing is implemented (Phase 7+)
        // For now, allow publishing without them - the folder will be created/updated
        // via upsert and TEE fields can be added later when the client supports it
        // Publish to delegated routing API with retries
        await this.publishToDelegatedRouting(dto.ipnsName, recordBytes);
        // Update or create folder tracking
        const folder = await this.upsertFolderIpns(userId, dto.ipnsName, dto.metadataCid, dto.encryptedIpnsPrivateKey, dto.keyEpoch);
        return {
            success: true,
            ipnsName: dto.ipnsName,
            sequenceNumber: folder.sequenceNumber,
        };
    }
    /**
     * Publish record to delegated routing API with exponential backoff retry
     */
    async publishToDelegatedRouting(ipnsName, recordBytes) {
        const url = `${this.delegatedRoutingUrl}/routing/v1/ipns/${ipnsName}`;
        let lastError = null;
        for (let attempt = 0; attempt < this.maxRetries; attempt++) {
            try {
                const response = await fetch(url, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/vnd.ipfs.ipns-record',
                    },
                    body: recordBytes,
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
                this.logger.error(`Delegated routing returned ${response.status} for ${ipnsName}: ${errorText}`);
                throw new Error(`Delegated routing returned ${response.status}`);
            }
            catch (error) {
                lastError = error instanceof Error ? error : new Error(String(error));
                // Only retry on network errors, not on HTTP errors
                if (lastError.message.includes('Delegated routing returned') &&
                    !lastError.message.includes('429')) {
                    // [SECURITY: MEDIUM-11] Generic error message to avoid leaking internal details
                    throw new common_1.HttpException('Failed to publish IPNS record to routing network', common_1.HttpStatus.BAD_GATEWAY);
                }
                // Exponential backoff for network errors
                if (attempt < this.maxRetries - 1) {
                    const delayMs = this.baseDelayMs * Math.pow(2, attempt);
                    this.logger.warn(`IPNS publish attempt ${attempt + 1} failed, retrying in ${delayMs}ms: ${lastError.message}`);
                    await this.delay(delayMs);
                }
            }
        }
        // [SECURITY: MEDIUM-11] Log full error, return generic message
        this.logger.error(`Failed to publish IPNS record after ${this.maxRetries} attempts: ${lastError?.message}`);
        throw new common_1.HttpException('Failed to publish IPNS record to routing network after multiple attempts', common_1.HttpStatus.BAD_GATEWAY);
    }
    /**
     * Create or update a folder IPNS entry
     */
    async upsertFolderIpns(userId, ipnsName, metadataCid, encryptedIpnsPrivateKey, keyEpoch) {
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
            if (encryptedIpnsPrivateKey && keyEpoch !== undefined) {
                this.republishService
                    .enrollFolder(userId, ipnsName, Buffer.from(encryptedIpnsPrivateKey, 'hex'), keyEpoch, metadataCid, saved.sequenceNumber)
                    .catch((err) => this.logger.warn(`Failed to enroll folder ${ipnsName} for republishing: ${err.message}`));
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
        if (encryptedIpnsPrivateKey && keyEpoch !== undefined) {
            this.republishService
                .enrollFolder(userId, ipnsName, Buffer.from(encryptedIpnsPrivateKey, 'hex'), keyEpoch, metadataCid, saved.sequenceNumber)
                .catch((err) => this.logger.warn(`Failed to enroll folder ${ipnsName} for republishing: ${err.message}`));
        }
        return saved;
    }
    /**
     * Get a folder IPNS entry by user and IPNS name
     */
    async getFolderIpns(userId, ipnsName) {
        return this.folderIpnsRepository.findOne({
            where: { userId, ipnsName },
        });
    }
    /**
     * Get all folder IPNS entries for a user (for TEE republishing)
     */
    async getAllFolderIpns(userId) {
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
    async resolveRecord(ipnsName) {
        let result = null;
        try {
            result = await this.resolveFromDelegatedRouting(ipnsName);
        }
        catch (error) {
            // Fall back to DB cache on BAD_GATEWAY (delegated routing failures)
            if (error instanceof common_1.HttpException && error.getStatus() === common_1.HttpStatus.BAD_GATEWAY) {
                this.logger.warn(`Delegated routing failed for ${ipnsName}, falling back to DB cache`);
            }
            else {
                throw error;
            }
        }
        if (result) {
            return result;
        }
        // Delegated routing returned null (404) or threw BAD_GATEWAY — try DB cache
        const cached = await this.folderIpnsRepository.findOne({
            where: { ipnsName },
        });
        if (cached?.latestCid) {
            this.logger.log(`Resolved ${ipnsName} from DB cache: ${cached.latestCid}`);
            return { cid: cached.latestCid, sequenceNumber: cached.sequenceNumber };
        }
        return null;
    }
    /**
     * Resolve an IPNS name via the delegated routing API with retries.
     * Returns null if the IPNS name is not found (404).
     * Throws HttpException (BAD_GATEWAY) on routing failures.
     */
    async resolveFromDelegatedRouting(ipnsName) {
        const url = `${this.delegatedRoutingUrl}/routing/v1/ipns/${ipnsName}`;
        let lastError = null;
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
                    const parsed = this.parseIpnsRecordBytes(recordBytes);
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
                this.logger.error(`Delegated routing resolution returned ${response.status} for ${ipnsName}: ${errorText}`);
                throw new Error(`Delegated routing returned ${response.status}`);
            }
            catch (error) {
                // Re-throw HttpException immediately (e.g., parsing errors) - don't retry
                if (error instanceof common_1.HttpException) {
                    throw error;
                }
                lastError = error instanceof Error ? error : new Error(String(error));
                // Only retry on network errors, not on HTTP errors
                if (lastError.message.includes('Delegated routing returned') &&
                    !lastError.message.includes('429')) {
                    // [SECURITY: MEDIUM-11] Generic error message to avoid leaking internal details
                    throw new common_1.HttpException('Failed to resolve IPNS name from routing network', common_1.HttpStatus.BAD_GATEWAY);
                }
                // Exponential backoff for network errors
                if (attempt < this.maxRetries - 1) {
                    const delayMs = this.baseDelayMs * Math.pow(2, attempt);
                    this.logger.warn(`IPNS resolve attempt ${attempt + 1} failed, retrying in ${delayMs}ms: ${lastError.message}`);
                    await this.delay(delayMs);
                }
            }
        }
        // [SECURITY: MEDIUM-11] Log full error, return generic message
        this.logger.error(`Failed to resolve IPNS name after ${this.maxRetries} attempts: ${lastError?.message}`);
        throw new common_1.HttpException('Failed to resolve IPNS name from routing network after multiple attempts', common_1.HttpStatus.BAD_GATEWAY);
    }
    /**
     * Parse an IPNS record to extract CID and sequence number
     * Uses inline protobuf decoder — no external dependencies
     */
    parseIpnsRecordBytes(recordBytes) {
        try {
            const record = (0, ipns_record_parser_1.parseIpnsRecord)(recordBytes);
            // Extract CID from the Value field (format: /ipfs/<cid>)
            const valuePath = record.value;
            const cidMatch = valuePath.match(/\/ipfs\/([a-zA-Z0-9]+)/);
            if (!cidMatch) {
                this.logger.error('Failed to extract CID from IPNS record value');
                throw new common_1.HttpException('Invalid IPNS record format', common_1.HttpStatus.BAD_GATEWAY);
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
        }
        catch (error) {
            if (error instanceof common_1.HttpException) {
                throw error;
            }
            this.logger.error(`Failed to parse IPNS record: ${error}`);
            throw new common_1.HttpException('Invalid IPNS record format', common_1.HttpStatus.BAD_GATEWAY);
        }
    }
    delay(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }
};
exports.IpnsService = IpnsService;
exports.IpnsService = IpnsService = IpnsService_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(folder_ipns_entity_1.FolderIpns)),
    __param(2, (0, common_1.Inject)((0, common_1.forwardRef)(() => republish_service_1.RepublishService))),
    __metadata("design:paramtypes", [typeorm_2.Repository,
        config_1.ConfigService,
        republish_service_1.RepublishService])
], IpnsService);
//# sourceMappingURL=ipns.service.js.map