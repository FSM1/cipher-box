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
Object.defineProperty(exports, "__esModule", { value: true });
exports.FolderIpns = void 0;
const typeorm_1 = require("typeorm");
const user_entity_1 = require("../../auth/entities/user.entity");
let FolderIpns = class FolderIpns {
    id;
    userId;
    user;
    /**
     * IPNS name (k51... CIDv1 format derived from Ed25519 public key)
     */
    ipnsName;
    /**
     * CID of the latest encrypted folder metadata
     * Null until first publish
     */
    latestCid;
    /**
     * IPNS record sequence number for ordering
     * Incremented on each publish
     */
    sequenceNumber; // TypeORM returns bigint as string
    /**
     * ECIES-wrapped Ed25519 private key for TEE republishing
     * Encrypted with TEE public key, only decryptable by TEE
     * Nullable until TEE integration is implemented (Phase 7+)
     */
    encryptedIpnsPrivateKey;
    /**
     * TEE key epoch the IPNS key was encrypted for
     * Used for key rotation tracking
     * Nullable until TEE integration is implemented (Phase 7+)
     */
    keyEpoch;
    /**
     * Marks the root folder for this user's vault
     */
    isRoot;
    createdAt;
    updatedAt;
};
exports.FolderIpns = FolderIpns;
__decorate([
    (0, typeorm_1.PrimaryGeneratedColumn)('uuid'),
    __metadata("design:type", String)
], FolderIpns.prototype, "id", void 0);
__decorate([
    (0, typeorm_1.Index)(),
    (0, typeorm_1.Column)({ type: 'uuid', name: 'user_id' }),
    __metadata("design:type", String)
], FolderIpns.prototype, "userId", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => user_entity_1.User, { onDelete: 'CASCADE' }),
    (0, typeorm_1.JoinColumn)({ name: 'user_id' }),
    __metadata("design:type", user_entity_1.User)
], FolderIpns.prototype, "user", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'varchar', length: 255, name: 'ipns_name' }),
    __metadata("design:type", String)
], FolderIpns.prototype, "ipnsName", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'varchar', length: 255, name: 'latest_cid', nullable: true }),
    __metadata("design:type", Object)
], FolderIpns.prototype, "latestCid", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'bigint', name: 'sequence_number', default: 0 }),
    __metadata("design:type", String)
], FolderIpns.prototype, "sequenceNumber", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'bytea', name: 'encrypted_ipns_private_key', nullable: true }),
    __metadata("design:type", Object)
], FolderIpns.prototype, "encryptedIpnsPrivateKey", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'int', name: 'key_epoch', nullable: true }),
    __metadata("design:type", Object)
], FolderIpns.prototype, "keyEpoch", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'boolean', name: 'is_root', default: false }),
    __metadata("design:type", Boolean)
], FolderIpns.prototype, "isRoot", void 0);
__decorate([
    (0, typeorm_1.CreateDateColumn)({ name: 'created_at' }),
    __metadata("design:type", Date)
], FolderIpns.prototype, "createdAt", void 0);
__decorate([
    (0, typeorm_1.UpdateDateColumn)({ name: 'updated_at' }),
    __metadata("design:type", Date)
], FolderIpns.prototype, "updatedAt", void 0);
exports.FolderIpns = FolderIpns = __decorate([
    (0, typeorm_1.Entity)('folder_ipns'),
    (0, typeorm_1.Unique)(['userId', 'ipnsName'])
], FolderIpns);
//# sourceMappingURL=folder-ipns.entity.js.map