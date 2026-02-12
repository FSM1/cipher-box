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
Object.defineProperty(exports, "__esModule", { value: true });
exports.VaultService = exports.QUOTA_LIMIT_BYTES = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const typeorm_2 = require("typeorm");
const vault_entity_1 = require("./entities/vault.entity");
const pinned_cid_entity_1 = require("./entities/pinned-cid.entity");
const folder_ipns_entity_1 = require("../ipns/entities/folder-ipns.entity");
const user_entity_1 = require("../auth/entities/user.entity");
const tee_key_state_service_1 = require("../tee/tee-key-state.service");
/**
 * Storage quota limit: 500 MiB
 */
exports.QUOTA_LIMIT_BYTES = 500 * 1024 * 1024; // 524,288,000 bytes
let VaultService = class VaultService {
    vaultRepository;
    pinnedCidRepository;
    folderIpnsRepository;
    userRepository;
    teeKeyStateService;
    constructor(vaultRepository, pinnedCidRepository, folderIpnsRepository, userRepository, teeKeyStateService) {
        this.vaultRepository = vaultRepository;
        this.pinnedCidRepository = pinnedCidRepository;
        this.folderIpnsRepository = folderIpnsRepository;
        this.userRepository = userRepository;
        this.teeKeyStateService = teeKeyStateService;
    }
    /**
     * Initialize a new vault for a user
     * Creates the vault with encrypted keys on first sign-in
     *
     * @throws ConflictException if vault already exists for user
     */
    async initializeVault(userId, dto) {
        // Check if vault already exists
        const existingVault = await this.vaultRepository.findOne({
            where: { ownerId: userId },
        });
        if (existingVault) {
            throw new common_1.ConflictException('Vault already exists for this user');
        }
        // Decode hex strings to buffers
        const vault = this.vaultRepository.create({
            ownerId: userId,
            ownerPublicKey: Buffer.from(dto.ownerPublicKey, 'hex'),
            encryptedRootFolderKey: Buffer.from(dto.encryptedRootFolderKey, 'hex'),
            encryptedRootIpnsPrivateKey: Buffer.from(dto.encryptedRootIpnsPrivateKey, 'hex'),
            rootIpnsPublicKey: Buffer.from(dto.rootIpnsPublicKey, 'hex'),
            rootIpnsName: dto.rootIpnsName,
            initializedAt: null,
        });
        const savedVault = await this.vaultRepository.save(vault);
        // Create root folder IPNS entry for publish tracking
        // This allows IPNS publishes to work without requiring TEE fields on every publish
        const rootFolderIpns = this.folderIpnsRepository.create({
            userId,
            ipnsName: dto.rootIpnsName,
            latestCid: null, // No content yet
            sequenceNumber: '0',
            encryptedIpnsPrivateKey: null, // TEE key added when TEE is implemented
            keyEpoch: null,
            isRoot: true,
        });
        await this.folderIpnsRepository.save(rootFolderIpns);
        const teeKeys = await this.teeKeyStateService.getTeeKeysDto();
        return this.toVaultResponse(savedVault, teeKeys);
    }
    /**
     * Get vault for a user
     *
     * @throws NotFoundException if vault does not exist
     */
    async getVault(userId) {
        const vault = await this.vaultRepository.findOne({
            where: { ownerId: userId },
        });
        if (!vault) {
            throw new common_1.NotFoundException('Vault not found');
        }
        const teeKeys = await this.teeKeyStateService.getTeeKeysDto();
        return this.toVaultResponse(vault, teeKeys);
    }
    /**
     * Check if vault exists for user (returns null if not)
     */
    async findVault(userId) {
        const vault = await this.vaultRepository.findOne({
            where: { ownerId: userId },
        });
        if (!vault)
            return null;
        const teeKeys = await this.teeKeyStateService.getTeeKeysDto();
        return this.toVaultResponse(vault, teeKeys);
    }
    /**
     * Get current storage quota usage for a user
     */
    async getQuota(userId) {
        const result = await this.pinnedCidRepository
            .createQueryBuilder('pin')
            .select('COALESCE(SUM(pin.size_bytes), 0)', 'total')
            .where('pin.user_id = :userId', { userId })
            .getRawOne();
        const usedBytes = parseInt(result?.total ?? '0', 10);
        const remainingBytes = Math.max(0, exports.QUOTA_LIMIT_BYTES - usedBytes);
        return {
            usedBytes,
            limitBytes: exports.QUOTA_LIMIT_BYTES,
            remainingBytes,
        };
    }
    /**
     * Check if user has sufficient quota for additional storage
     *
     * @returns true if (current usage + additionalBytes) <= quota limit
     */
    async checkQuota(userId, additionalBytes) {
        const quota = await this.getQuota(userId);
        return quota.usedBytes + additionalBytes <= exports.QUOTA_LIMIT_BYTES;
    }
    /**
     * Record a pinned CID for quota tracking
     * Uses upsert (ON CONFLICT DO NOTHING) for idempotency
     */
    async recordPin(userId, cid, sizeBytes) {
        await this.pinnedCidRepository
            .createQueryBuilder()
            .insert()
            .into(pinned_cid_entity_1.PinnedCid)
            .values({
            userId,
            cid,
            sizeBytes: sizeBytes.toString(),
        })
            .orIgnore() // ON CONFLICT DO NOTHING for idempotency
            .execute();
    }
    /**
     * Remove a pinned CID record
     * Idempotent - no error if CID not found
     */
    async recordUnpin(userId, cid) {
        await this.pinnedCidRepository.delete({
            userId,
            cid,
        });
    }
    /**
     * Mark vault as initialized (first file uploaded)
     */
    async markInitialized(userId) {
        await this.vaultRepository.update({ ownerId: userId }, { initializedAt: new Date() });
    }
    /**
     * Get export data for independent recovery.
     * Returns the minimal set of fields needed to reconstruct the vault:
     * root IPNS name + encrypted root keys + derivation hints.
     */
    async getExportData(userId) {
        const vault = await this.vaultRepository.findOne({
            where: { ownerId: userId },
        });
        if (!vault) {
            throw new common_1.NotFoundException('Vault not found');
        }
        const user = await this.userRepository.findOne({
            where: { id: userId },
        });
        // Determine derivation info from user's derivationVersion
        let derivationInfo = null;
        if (user) {
            derivationInfo = {
                method: user.derivationVersion === null ? 'web3auth' : 'external-wallet',
                derivationVersion: user.derivationVersion,
            };
        }
        return {
            format: 'cipherbox-vault-export',
            version: '1.0',
            exportedAt: new Date().toISOString(),
            rootIpnsName: vault.rootIpnsName,
            encryptedRootFolderKey: vault.encryptedRootFolderKey.toString('hex'),
            encryptedRootIpnsPrivateKey: vault.encryptedRootIpnsPrivateKey.toString('hex'),
            derivationInfo,
        };
    }
    /**
     * Convert Vault entity to response DTO with hex-encoded fields
     */
    toVaultResponse(vault, teeKeys = null) {
        return {
            id: vault.id,
            ownerPublicKey: vault.ownerPublicKey.toString('hex'),
            encryptedRootFolderKey: vault.encryptedRootFolderKey.toString('hex'),
            encryptedRootIpnsPrivateKey: vault.encryptedRootIpnsPrivateKey.toString('hex'),
            rootIpnsPublicKey: vault.rootIpnsPublicKey.toString('hex'),
            rootIpnsName: vault.rootIpnsName,
            createdAt: vault.createdAt,
            initializedAt: vault.initializedAt,
            teeKeys,
        };
    }
};
exports.VaultService = VaultService;
exports.VaultService = VaultService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(vault_entity_1.Vault)),
    __param(1, (0, typeorm_1.InjectRepository)(pinned_cid_entity_1.PinnedCid)),
    __param(2, (0, typeorm_1.InjectRepository)(folder_ipns_entity_1.FolderIpns)),
    __param(3, (0, typeorm_1.InjectRepository)(user_entity_1.User)),
    __metadata("design:paramtypes", [typeorm_2.Repository,
        typeorm_2.Repository,
        typeorm_2.Repository,
        typeorm_2.Repository,
        tee_key_state_service_1.TeeKeyStateService])
], VaultService);
//# sourceMappingURL=vault.service.js.map