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
exports.IpnsRepublishSchedule = void 0;
const typeorm_1 = require("typeorm");
const user_entity_1 = require("../auth/entities/user.entity");
let IpnsRepublishSchedule = class IpnsRepublishSchedule {
    id;
    userId;
    user;
    /**
     * IPNS name being republished (k51... or bafzaa... format)
     */
    ipnsName;
    /**
     * TEE-encrypted Ed25519 private key for IPNS signing.
     * Only decryptable by the TEE worker.
     */
    encryptedIpnsKey;
    /**
     * TEE key epoch this encrypted key was created for.
     * Used for grace period migration during epoch rotation.
     */
    keyEpoch;
    /**
     * Most recent metadata CID to republish
     */
    latestCid;
    /**
     * Current IPNS sequence number.
     * TypeORM returns bigint as string to avoid JavaScript precision issues.
     */
    sequenceNumber;
    /**
     * When the next republish is due
     */
    nextRepublishAt;
    /**
     * When the last successful republish occurred
     */
    lastRepublishAt;
    /**
     * Number of consecutive failures.
     * Resets to 0 on success.
     */
    consecutiveFailures;
    /**
     * Scheduling status:
     * - 'active': normal republish scheduling
     * - 'retrying': has failed, retrying with backoff
     * - 'stale': exceeded max failures, needs intervention or TEE recovery
     */
    status;
    /**
     * Last failure error message for debugging.
     * NEVER contains key material.
     */
    lastError;
    createdAt;
    updatedAt;
};
exports.IpnsRepublishSchedule = IpnsRepublishSchedule;
__decorate([
    (0, typeorm_1.PrimaryGeneratedColumn)('uuid'),
    __metadata("design:type", String)
], IpnsRepublishSchedule.prototype, "id", void 0);
__decorate([
    (0, typeorm_1.Index)(),
    (0, typeorm_1.Column)({ type: 'uuid', name: 'user_id' }),
    __metadata("design:type", String)
], IpnsRepublishSchedule.prototype, "userId", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => user_entity_1.User, { onDelete: 'CASCADE' }),
    (0, typeorm_1.JoinColumn)({ name: 'user_id' }),
    __metadata("design:type", user_entity_1.User)
], IpnsRepublishSchedule.prototype, "user", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'varchar', length: 255, name: 'ipns_name' }),
    __metadata("design:type", String)
], IpnsRepublishSchedule.prototype, "ipnsName", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'bytea', name: 'encrypted_ipns_key' }),
    __metadata("design:type", Buffer)
], IpnsRepublishSchedule.prototype, "encryptedIpnsKey", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'int', name: 'key_epoch' }),
    __metadata("design:type", Number)
], IpnsRepublishSchedule.prototype, "keyEpoch", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'varchar', length: 255, name: 'latest_cid' }),
    __metadata("design:type", String)
], IpnsRepublishSchedule.prototype, "latestCid", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'bigint', name: 'sequence_number', default: 0 }),
    __metadata("design:type", String)
], IpnsRepublishSchedule.prototype, "sequenceNumber", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'timestamp', name: 'next_republish_at' }),
    __metadata("design:type", Date)
], IpnsRepublishSchedule.prototype, "nextRepublishAt", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'timestamp', name: 'last_republish_at', nullable: true }),
    __metadata("design:type", Object)
], IpnsRepublishSchedule.prototype, "lastRepublishAt", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'int', name: 'consecutive_failures', default: 0 }),
    __metadata("design:type", Number)
], IpnsRepublishSchedule.prototype, "consecutiveFailures", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'varchar', length: 20, default: 'active' }),
    __metadata("design:type", String)
], IpnsRepublishSchedule.prototype, "status", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'text', name: 'last_error', nullable: true }),
    __metadata("design:type", Object)
], IpnsRepublishSchedule.prototype, "lastError", void 0);
__decorate([
    (0, typeorm_1.CreateDateColumn)({ name: 'created_at' }),
    __metadata("design:type", Date)
], IpnsRepublishSchedule.prototype, "createdAt", void 0);
__decorate([
    (0, typeorm_1.UpdateDateColumn)({ name: 'updated_at' }),
    __metadata("design:type", Date)
], IpnsRepublishSchedule.prototype, "updatedAt", void 0);
exports.IpnsRepublishSchedule = IpnsRepublishSchedule = __decorate([
    (0, typeorm_1.Entity)('ipns_republish_schedule'),
    (0, typeorm_1.Unique)(['userId', 'ipnsName']),
    (0, typeorm_1.Index)(['status', 'nextRepublishAt'])
], IpnsRepublishSchedule);
//# sourceMappingURL=republish-schedule.entity.js.map