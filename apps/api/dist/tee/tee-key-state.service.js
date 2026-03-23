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
var TeeKeyStateService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.TeeKeyStateService = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const typeorm_2 = require("typeorm");
const tee_key_state_entity_1 = require("./tee-key-state.entity");
const tee_key_rotation_log_entity_1 = require("./tee-key-rotation-log.entity");
/**
 * Grace period duration: 4 weeks (in milliseconds)
 */
const GRACE_PERIOD_MS = 4 * 7 * 24 * 60 * 60 * 1000;
let TeeKeyStateService = TeeKeyStateService_1 = class TeeKeyStateService {
    keyStateRepository;
    rotationLogRepository;
    dataSource;
    logger = new common_1.Logger(TeeKeyStateService_1.name);
    constructor(keyStateRepository, rotationLogRepository, dataSource) {
        this.keyStateRepository = keyStateRepository;
        this.rotationLogRepository = rotationLogRepository;
        this.dataSource = dataSource;
    }
    /**
     * Get the current TEE key state (singleton row).
     * Returns null if TEE has not been initialized yet.
     */
    async getCurrentState() {
        const states = await this.keyStateRepository.find({ take: 1 });
        return states.length > 0 ? states[0] : null;
    }
    /**
     * Get TEE public keys formatted for API responses.
     * Returns null if TEE has not been initialized yet.
     */
    async getTeeKeysDto() {
        const state = await this.getCurrentState();
        if (!state) {
            return null;
        }
        return {
            currentEpoch: state.currentEpoch,
            currentPublicKey: state.currentPublicKey.toString('hex'),
            previousEpoch: state.previousEpoch,
            previousPublicKey: state.previousPublicKey ? state.previousPublicKey.toString('hex') : null,
        };
    }
    /**
     * Initialize the first TEE key epoch.
     * Used on first boot when tee_key_state is empty.
     */
    async initializeEpoch(epoch, publicKey) {
        const existing = await this.getCurrentState();
        if (existing) {
            throw new Error('TEE key state already initialized. Use rotateEpoch for updates.');
        }
        const state = this.keyStateRepository.create({
            currentEpoch: epoch,
            currentPublicKey: Buffer.from(publicKey),
            previousEpoch: null,
            previousPublicKey: null,
            gracePeriodEndsAt: null,
        });
        const saved = await this.keyStateRepository.save(state);
        this.logger.log(`TEE key state initialized at epoch ${epoch}`);
        return saved;
    }
    /**
     * Rotate to a new TEE key epoch.
     * Shifts current -> previous, sets new current, starts grace period.
     * Uses a transaction to ensure atomicity.
     */
    async rotateEpoch(newEpoch, newPublicKey, reason) {
        return this.dataSource.transaction(async (manager) => {
            const keyStateRepo = manager.getRepository(tee_key_state_entity_1.TeeKeyState);
            const rotationLogRepo = manager.getRepository(tee_key_rotation_log_entity_1.TeeKeyRotationLog);
            const states = await keyStateRepo.find({ take: 1 });
            if (states.length === 0) {
                throw new Error('Cannot rotate: TEE key state not initialized. Call initializeEpoch first.');
            }
            const state = states[0];
            // Log the rotation
            const log = rotationLogRepo.create({
                fromEpoch: state.currentEpoch,
                toEpoch: newEpoch,
                fromPublicKey: state.currentPublicKey,
                toPublicKey: Buffer.from(newPublicKey),
                reason,
            });
            await rotationLogRepo.save(log);
            // Shift current to previous, set new current
            state.previousEpoch = state.currentEpoch;
            state.previousPublicKey = state.currentPublicKey;
            state.currentEpoch = newEpoch;
            state.currentPublicKey = Buffer.from(newPublicKey);
            state.gracePeriodEndsAt = new Date(Date.now() + GRACE_PERIOD_MS);
            const saved = await keyStateRepo.save(state);
            this.logger.log(`TEE key rotated: epoch ${log.fromEpoch} -> ${newEpoch}, reason: ${reason}, grace period ends: ${saved.gracePeriodEndsAt?.toISOString()}`);
            return saved;
        });
    }
    /**
     * Check if the previous epoch's grace period is still active.
     * Returns true if there is a previous epoch and its grace period has not expired.
     */
    async isGracePeriodActive() {
        const state = await this.getCurrentState();
        if (!state || !state.gracePeriodEndsAt) {
            return false;
        }
        return new Date() < state.gracePeriodEndsAt;
    }
    /**
     * Get the rotation history, most recent first.
     */
    async getRotationHistory(limit = 10) {
        return this.rotationLogRepository.find({
            order: { createdAt: 'DESC' },
            take: limit,
        });
    }
    /**
     * Clear the previous epoch fields after the grace period has ended.
     * Called by the scheduler after the grace period expires.
     */
    async deprecatePreviousEpoch() {
        const state = await this.getCurrentState();
        if (!state) {
            return;
        }
        if (!state.previousEpoch) {
            this.logger.debug('No previous epoch to deprecate');
            return;
        }
        if (state.gracePeriodEndsAt && new Date() < state.gracePeriodEndsAt) {
            this.logger.warn('Grace period still active, not deprecating previous epoch');
            return;
        }
        const deprecatedEpoch = state.previousEpoch;
        state.previousEpoch = null;
        state.previousPublicKey = null;
        state.gracePeriodEndsAt = null;
        await this.keyStateRepository.save(state);
        this.logger.log(`Previous TEE epoch ${deprecatedEpoch} deprecated`);
    }
};
exports.TeeKeyStateService = TeeKeyStateService;
exports.TeeKeyStateService = TeeKeyStateService = TeeKeyStateService_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(tee_key_state_entity_1.TeeKeyState)),
    __param(1, (0, typeorm_1.InjectRepository)(tee_key_rotation_log_entity_1.TeeKeyRotationLog)),
    __metadata("design:paramtypes", [typeorm_2.Repository,
        typeorm_2.Repository,
        typeorm_2.DataSource])
], TeeKeyStateService);
//# sourceMappingURL=tee-key-state.service.js.map