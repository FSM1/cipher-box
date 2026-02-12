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
exports.Vault = void 0;
const typeorm_1 = require("typeorm");
const user_entity_1 = require("../../auth/entities/user.entity");
let Vault = class Vault {
    id;
    ownerId;
    owner;
    /**
     * User's secp256k1 public key (uncompressed, 65 bytes)
     * Used for ECIES encryption of vault keys
     */
    ownerPublicKey;
    /**
     * ECIES-wrapped root folder AES-256 key
     * Encrypted with ownerPublicKey, only decryptable by user's private key
     */
    encryptedRootFolderKey;
    /**
     * ECIES-wrapped Ed25519 IPNS private key
     * Used for signing root folder IPNS records
     */
    encryptedRootIpnsPrivateKey;
    /**
     * Ed25519 IPNS public key (32 bytes)
     * Stored in plaintext (not secret) - needed to reconstruct keypair after decryption
     */
    rootIpnsPublicKey;
    /**
     * IPNS name (libp2p-key multihash of public key)
     * Used to identify the root folder's IPNS record
     */
    rootIpnsName;
    createdAt;
    /**
     * Set when vault is first used (first file uploaded)
     * Null until vault contains actual content
     */
    initializedAt;
    updatedAt;
};
exports.Vault = Vault;
__decorate([
    (0, typeorm_1.PrimaryGeneratedColumn)('uuid'),
    __metadata("design:type", String)
], Vault.prototype, "id", void 0);
__decorate([
    (0, typeorm_1.Index)({ unique: true }),
    (0, typeorm_1.Column)({ type: 'uuid', name: 'owner_id' }),
    __metadata("design:type", String)
], Vault.prototype, "ownerId", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => user_entity_1.User, { onDelete: 'CASCADE' }),
    (0, typeorm_1.JoinColumn)({ name: 'owner_id' }),
    __metadata("design:type", user_entity_1.User)
], Vault.prototype, "owner", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'bytea', name: 'owner_public_key' }),
    __metadata("design:type", Buffer)
], Vault.prototype, "ownerPublicKey", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'bytea', name: 'encrypted_root_folder_key' }),
    __metadata("design:type", Buffer)
], Vault.prototype, "encryptedRootFolderKey", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'bytea', name: 'encrypted_root_ipns_private_key' }),
    __metadata("design:type", Buffer)
], Vault.prototype, "encryptedRootIpnsPrivateKey", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'bytea', name: 'root_ipns_public_key' }),
    __metadata("design:type", Buffer)
], Vault.prototype, "rootIpnsPublicKey", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'varchar', length: 255, name: 'root_ipns_name' }),
    __metadata("design:type", String)
], Vault.prototype, "rootIpnsName", void 0);
__decorate([
    (0, typeorm_1.CreateDateColumn)({ name: 'created_at' }),
    __metadata("design:type", Date)
], Vault.prototype, "createdAt", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'timestamp', nullable: true, name: 'initialized_at' }),
    __metadata("design:type", Object)
], Vault.prototype, "initializedAt", void 0);
__decorate([
    (0, typeorm_1.UpdateDateColumn)({ name: 'updated_at' }),
    __metadata("design:type", Date)
], Vault.prototype, "updatedAt", void 0);
exports.Vault = Vault = __decorate([
    (0, typeorm_1.Entity)('vaults')
], Vault);
//# sourceMappingURL=vault.entity.js.map