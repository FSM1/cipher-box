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
exports.TeeKeyState = void 0;
const typeorm_1 = require("typeorm");
/**
 * Singleton-row entity tracking the current and previous TEE key epochs.
 * The CipherBox backend uses this to know which TEE public key to give clients
 * for encrypting IPNS private keys, and to manage grace-period key rotation.
 */
let TeeKeyState = class TeeKeyState {
    id;
    /**
     * Current active TEE key epoch number
     */
    currentEpoch;
    /**
     * Current epoch's uncompressed secp256k1 public key (65 bytes, 0x04 prefix)
     */
    currentPublicKey;
    /**
     * Previous TEE key epoch number (null if no rotation has occurred)
     */
    previousEpoch;
    /**
     * Previous epoch's uncompressed secp256k1 public key (65 bytes, 0x04 prefix)
     * Null if no rotation has occurred
     */
    previousPublicKey;
    /**
     * When the previous epoch's grace period ends.
     * After this timestamp, the previous epoch key is deprecated.
     * Null if no rotation has occurred or grace period already ended.
     */
    gracePeriodEndsAt;
    createdAt;
    updatedAt;
};
exports.TeeKeyState = TeeKeyState;
__decorate([
    (0, typeorm_1.PrimaryGeneratedColumn)('uuid'),
    __metadata("design:type", String)
], TeeKeyState.prototype, "id", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'int', name: 'current_epoch', nullable: false }),
    __metadata("design:type", Number)
], TeeKeyState.prototype, "currentEpoch", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'bytea', name: 'current_public_key', nullable: false }),
    __metadata("design:type", Buffer)
], TeeKeyState.prototype, "currentPublicKey", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'int', name: 'previous_epoch', nullable: true }),
    __metadata("design:type", Object)
], TeeKeyState.prototype, "previousEpoch", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'bytea', name: 'previous_public_key', nullable: true }),
    __metadata("design:type", Object)
], TeeKeyState.prototype, "previousPublicKey", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'timestamp', name: 'grace_period_ends_at', nullable: true }),
    __metadata("design:type", Object)
], TeeKeyState.prototype, "gracePeriodEndsAt", void 0);
__decorate([
    (0, typeorm_1.CreateDateColumn)({ name: 'created_at' }),
    __metadata("design:type", Date)
], TeeKeyState.prototype, "createdAt", void 0);
__decorate([
    (0, typeorm_1.UpdateDateColumn)({ name: 'updated_at' }),
    __metadata("design:type", Date)
], TeeKeyState.prototype, "updatedAt", void 0);
exports.TeeKeyState = TeeKeyState = __decorate([
    (0, typeorm_1.Entity)('tee_key_state')
], TeeKeyState);
//# sourceMappingURL=tee-key-state.entity.js.map