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
var TeeService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.TeeService = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const tee_key_state_service_1 = require("./tee-key-state.service");
/** Default timeout for TEE worker HTTP requests (30 seconds) */
const TEE_REQUEST_TIMEOUT_MS = 30_000;
let TeeService = TeeService_1 = class TeeService {
    configService;
    teeKeyStateService;
    logger = new common_1.Logger(TeeService_1.name);
    teeWorkerUrl;
    teeWorkerSecret;
    constructor(configService, teeKeyStateService) {
        this.configService = configService;
        this.teeKeyStateService = teeKeyStateService;
        this.teeWorkerUrl = this.configService.get('TEE_WORKER_URL', 'http://localhost:3001');
        this.teeWorkerSecret = this.configService.get('TEE_WORKER_SECRET', '');
    }
    /**
     * Check TEE worker health and get current epoch.
     */
    async getHealth() {
        const response = await this.fetchWithTimeout(`${this.teeWorkerUrl}/health`, {
            method: 'GET',
            headers: this.authHeaders(),
        });
        if (!response.ok) {
            throw new Error(`TEE worker health check failed: HTTP ${response.status}`);
        }
        const data = (await response.json());
        return data;
    }
    /**
     * Get the TEE worker's public key for a specific epoch.
     * Returns the 65-byte uncompressed secp256k1 public key.
     */
    async getPublicKey(epoch) {
        const response = await this.fetchWithTimeout(`${this.teeWorkerUrl}/public-key?epoch=${epoch}`, {
            method: 'GET',
            headers: this.authHeaders(),
        });
        if (!response.ok) {
            throw new Error(`TEE worker public key request failed: HTTP ${response.status}`);
        }
        const data = (await response.json());
        const publicKeyBytes = new Uint8Array(Buffer.from(data.publicKey, 'hex'));
        if (publicKeyBytes.length !== 65 || publicKeyBytes[0] !== 0x04) {
            throw new Error(`Invalid TEE public key: expected 65 bytes with 0x04 prefix, got ${publicKeyBytes.length} bytes`);
        }
        return publicKeyBytes;
    }
    /**
     * Send a batch of entries to the TEE worker for IPNS record signing.
     * The TEE worker decrypts IPNS keys, signs new records, and returns results.
     */
    async republish(entries) {
        this.logger.log(`Sending ${entries.length} entries to TEE worker for republishing`);
        const response = await this.fetchWithTimeout(`${this.teeWorkerUrl}/republish`, {
            method: 'POST',
            headers: {
                ...this.authHeaders(),
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ entries }),
        });
        if (!response.ok) {
            throw new Error(`TEE worker republish failed: HTTP ${response.status}`);
        }
        const data = (await response.json());
        const successCount = data.results.filter((r) => r.success).length;
        this.logger.log(`TEE republish complete: ${successCount}/${data.results.length} entries succeeded`);
        return data.results;
    }
    /**
     * Initialize TEE key state from the TEE worker on module startup.
     * If tee_key_state is empty, queries TEE for epoch 1 public key and initializes.
     * If tee_key_state has data, validates it still matches the TEE worker.
     * Gracefully handles TEE worker being unavailable (logs warning, does not throw).
     */
    async initializeFromTee() {
        try {
            // Check TEE worker health first
            const health = await this.getHealth();
            this.logger.log(`TEE worker healthy, current epoch: ${health.epoch}`);
            const currentState = await this.teeKeyStateService.getCurrentState();
            if (!currentState) {
                // First boot: initialize from TEE worker
                const publicKey = await this.getPublicKey(health.epoch);
                await this.teeKeyStateService.initializeEpoch(health.epoch, publicKey);
                this.logger.log(`TEE key state initialized from worker at epoch ${health.epoch}`);
                return;
            }
            // Validate existing state matches TEE worker
            if (currentState.currentEpoch !== health.epoch) {
                this.logger.warn(`TEE epoch mismatch: DB has epoch ${currentState.currentEpoch}, TEE worker reports epoch ${health.epoch}. ` +
                    'This may indicate a TEE worker update. Manual epoch rotation may be needed.');
            }
            else {
                this.logger.log(`TEE key state validated: epoch ${currentState.currentEpoch} matches worker`);
            }
        }
        catch (error) {
            // TEE worker unavailable - this is expected during development
            // and acceptable for startup (republishing will retry later)
            const message = error instanceof Error ? error.message : String(error);
            this.logger.warn(`TEE worker unavailable during initialization: ${message}`);
            this.logger.warn('TEE republishing will not work until the TEE worker is available. ' +
                'This is expected in development without a TEE simulator.');
        }
    }
    /**
     * Build authorization headers for TEE worker requests.
     * IMPORTANT: Never log the secret value.
     */
    authHeaders() {
        const headers = {};
        if (this.teeWorkerSecret) {
            headers['Authorization'] = `Bearer ${this.teeWorkerSecret}`;
        }
        return headers;
    }
    /**
     * Fetch with a timeout to prevent hanging requests.
     */
    async fetchWithTimeout(url, init) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), TEE_REQUEST_TIMEOUT_MS);
        try {
            return await fetch(url, {
                ...init,
                signal: controller.signal,
            });
        }
        catch (error) {
            if (error instanceof Error && error.name === 'AbortError') {
                throw new Error(`TEE worker request timed out after ${TEE_REQUEST_TIMEOUT_MS}ms: ${url}`);
            }
            throw error;
        }
        finally {
            clearTimeout(timeout);
        }
    }
};
exports.TeeService = TeeService;
exports.TeeService = TeeService = TeeService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [config_1.ConfigService,
        tee_key_state_service_1.TeeKeyStateService])
], TeeService);
//# sourceMappingURL=tee.service.js.map