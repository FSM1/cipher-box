import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TeeKeyStateService } from './tee-key-state.service';

/**
 * A single entry in a batch republish request to the TEE worker.
 */
export interface RepublishEntry {
  /** Base64-encoded ECIES-encrypted IPNS Ed25519 private key */
  encryptedIpnsKey: string;
  /** TEE key epoch the IPNS key was encrypted for */
  keyEpoch: number;
  /** IPNS name (k51... or bafzaa...) */
  ipnsName: string;
  /** CID of the latest encrypted folder metadata */
  latestCid: string;
  /** Current IPNS sequence number (bigint as string) */
  sequenceNumber: string;
}

/**
 * Result for a single entry in a batch republish response from the TEE worker.
 */
export interface RepublishResult {
  /** IPNS name this result corresponds to */
  ipnsName: string;
  /** Whether the signing succeeded */
  success: boolean;
  /** Base64-encoded signed IPNS record (present on success) */
  signedRecord?: string;
  /** New sequence number after signing (present on success) */
  newSequenceNumber?: string;
  /** Base64-encoded re-encrypted IPNS key if epoch was upgraded (present if key epoch changed) */
  upgradedEncryptedKey?: string;
  /** New key epoch if the key was re-encrypted (present if key epoch changed) */
  upgradedKeyEpoch?: number;
  /** Error message (present on failure) */
  error?: string;
}

/** Default timeout for TEE worker HTTP requests (30 seconds) */
const TEE_REQUEST_TIMEOUT_MS = 30_000;

@Injectable()
export class TeeService {
  private readonly logger = new Logger(TeeService.name);
  private readonly teeWorkerUrl: string;
  private readonly teeWorkerSecret: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly teeKeyStateService: TeeKeyStateService
  ) {
    this.teeWorkerUrl = this.configService.get<string>('TEE_WORKER_URL', 'http://localhost:3001');
    this.teeWorkerSecret = this.configService.get<string>('TEE_WORKER_SECRET', '');
  }

  /**
   * Check TEE worker health and get current epoch.
   */
  async getHealth(): Promise<{ healthy: boolean; epoch: number }> {
    const response = await this.fetchWithTimeout(`${this.teeWorkerUrl}/health`, {
      method: 'GET',
      headers: this.authHeaders(),
    });

    if (!response.ok) {
      throw new Error(`TEE worker health check failed: HTTP ${response.status}`);
    }

    const data = (await response.json()) as { healthy: boolean; epoch: number };
    return data;
  }

  /**
   * Get the TEE worker's public key for a specific epoch.
   * Returns the 65-byte uncompressed secp256k1 public key.
   */
  async getPublicKey(epoch: number): Promise<Uint8Array> {
    const response = await this.fetchWithTimeout(`${this.teeWorkerUrl}/public-key?epoch=${epoch}`, {
      method: 'GET',
      headers: this.authHeaders(),
    });

    if (!response.ok) {
      throw new Error(`TEE worker public key request failed: HTTP ${response.status}`);
    }

    const data = (await response.json()) as { publicKey: string };
    const publicKeyBytes = Uint8Array.from(atob(data.publicKey), (c) => c.charCodeAt(0));

    if (publicKeyBytes.length !== 65 || publicKeyBytes[0] !== 0x04) {
      throw new Error(
        `Invalid TEE public key: expected 65 bytes with 0x04 prefix, got ${publicKeyBytes.length} bytes`
      );
    }

    return publicKeyBytes;
  }

  /**
   * Send a batch of entries to the TEE worker for IPNS record signing.
   * The TEE worker decrypts IPNS keys, signs new records, and returns results.
   */
  async republish(entries: RepublishEntry[]): Promise<RepublishResult[]> {
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

    const data = (await response.json()) as { results: RepublishResult[] };
    const successCount = data.results.filter((r) => r.success).length;
    this.logger.log(
      `TEE republish complete: ${successCount}/${data.results.length} entries succeeded`
    );

    return data.results;
  }

  /**
   * Initialize TEE key state from the TEE worker on module startup.
   * If tee_key_state is empty, queries TEE for epoch 1 public key and initializes.
   * If tee_key_state has data, validates it still matches the TEE worker.
   * Gracefully handles TEE worker being unavailable (logs warning, does not throw).
   */
  async initializeFromTee(): Promise<void> {
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
        this.logger.warn(
          `TEE epoch mismatch: DB has epoch ${currentState.currentEpoch}, TEE worker reports epoch ${health.epoch}. ` +
            'This may indicate a TEE worker update. Manual epoch rotation may be needed.'
        );
      } else {
        this.logger.log(
          `TEE key state validated: epoch ${currentState.currentEpoch} matches worker`
        );
      }
    } catch (error) {
      // TEE worker unavailable - this is expected during development
      // and acceptable for startup (republishing will retry later)
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`TEE worker unavailable during initialization: ${message}`);
      this.logger.warn(
        'TEE republishing will not work until the TEE worker is available. ' +
          'This is expected in development without a TEE simulator.'
      );
    }
  }

  /**
   * Build authorization headers for TEE worker requests.
   * IMPORTANT: Never log the secret value.
   */
  private authHeaders(): Record<string, string> {
    const headers: Record<string, string> = {};
    if (this.teeWorkerSecret) {
      headers['Authorization'] = `Bearer ${this.teeWorkerSecret}`;
    }
    return headers;
  }

  /**
   * Fetch with a timeout to prevent hanging requests.
   */
  private async fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TEE_REQUEST_TIMEOUT_MS);

    try {
      return await fetch(url, {
        ...init,
        signal: controller.signal,
      });
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`TEE worker request timed out after ${TEE_REQUEST_TIMEOUT_MS}ms: ${url}`);
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }
}
