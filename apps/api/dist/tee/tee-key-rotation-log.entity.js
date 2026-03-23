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
exports.TeeKeyRotationLog = void 0;
const typeorm_1 = require("typeorm");
/**
 * Audit log for TEE key epoch rotations.
 * Records every rotation event for debugging and compliance.
 */
let TeeKeyRotationLog = class TeeKeyRotationLog {
    id;
    /**
     * Epoch number before rotation
     */
    fromEpoch;
    /**
     * Epoch number after rotation
     */
    toEpoch;
    /**
     * Public key of the from-epoch (65 bytes uncompressed secp256k1)
     */
    fromPublicKey;
    /**
     * Public key of the to-epoch (65 bytes uncompressed secp256k1)
     */
    toPublicKey;
    /**
     * Reason for rotation: 'scheduled', 'cvm_update', 'manual'
     */
    reason;
    createdAt;
};
exports.TeeKeyRotationLog = TeeKeyRotationLog;
__decorate([
    (0, typeorm_1.PrimaryGeneratedColumn)('uuid'),
    __metadata("design:type", String)
], TeeKeyRotationLog.prototype, "id", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'int', name: 'from_epoch' }),
    __metadata("design:type", Number)
], TeeKeyRotationLog.prototype, "fromEpoch", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'int', name: 'to_epoch' }),
    __metadata("design:type", Number)
], TeeKeyRotationLog.prototype, "toEpoch", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'bytea', name: 'from_public_key' }),
    __metadata("design:type", Buffer)
], TeeKeyRotationLog.prototype, "fromPublicKey", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'bytea', name: 'to_public_key' }),
    __metadata("design:type", Buffer)
], TeeKeyRotationLog.prototype, "toPublicKey", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'varchar', length: 255 }),
    __metadata("design:type", String)
], TeeKeyRotationLog.prototype, "reason", void 0);
__decorate([
    (0, typeorm_1.CreateDateColumn)({ name: 'created_at' }),
    __metadata("design:type", Date)
], TeeKeyRotationLog.prototype, "createdAt", void 0);
exports.TeeKeyRotationLog = TeeKeyRotationLog = __decorate([
    (0, typeorm_1.Entity)('tee_key_rotation_log')
], TeeKeyRotationLog);
//# sourceMappingURL=tee-key-rotation-log.entity.js.map