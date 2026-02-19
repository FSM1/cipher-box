import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, Repository } from 'typeorm';
import { TeeKeyState } from './tee-key-state.entity';
import { TeeKeyRotationLog } from './tee-key-rotation-log.entity';
import { TeeKeysDto } from './dto/tee-keys.dto';

/**
 * Grace period duration: 4 weeks (in milliseconds)
 */
const GRACE_PERIOD_MS = 4 * 7 * 24 * 60 * 60 * 1000;

@Injectable()
export class TeeKeyStateService {
  private readonly logger = new Logger(TeeKeyStateService.name);

  constructor(
    @InjectRepository(TeeKeyState)
    private readonly keyStateRepository: Repository<TeeKeyState>,
    @InjectRepository(TeeKeyRotationLog)
    private readonly rotationLogRepository: Repository<TeeKeyRotationLog>,
    private readonly dataSource: DataSource
  ) {}

  /**
   * Get the current TEE key state (singleton row).
   * Returns null if TEE has not been initialized yet.
   */
  async getCurrentState(): Promise<TeeKeyState | null> {
    const states = await this.keyStateRepository.find({ take: 1 });
    return states.length > 0 ? states[0] : null;
  }

  /**
   * Get TEE public keys formatted for API responses.
   * Returns null if TEE has not been initialized yet.
   */
  async getTeeKeysDto(): Promise<TeeKeysDto | null> {
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
  async initializeEpoch(epoch: number, publicKey: Uint8Array): Promise<TeeKeyState> {
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
  async rotateEpoch(
    newEpoch: number,
    newPublicKey: Uint8Array,
    reason: string
  ): Promise<TeeKeyState> {
    return this.dataSource.transaction(async (manager) => {
      const keyStateRepo = manager.getRepository(TeeKeyState);
      const rotationLogRepo = manager.getRepository(TeeKeyRotationLog);

      const states = await keyStateRepo.find({ take: 1 });
      if (states.length === 0) {
        throw new Error(
          'Cannot rotate: TEE key state not initialized. Call initializeEpoch first.'
        );
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
      this.logger.log(
        `TEE key rotated: epoch ${log.fromEpoch} -> ${newEpoch}, reason: ${reason}, grace period ends: ${saved.gracePeriodEndsAt?.toISOString()}`
      );
      return saved;
    });
  }

  /**
   * Check if the previous epoch's grace period is still active.
   * Returns true if there is a previous epoch and its grace period has not expired.
   */
  async isGracePeriodActive(): Promise<boolean> {
    const state = await this.getCurrentState();
    if (!state || !state.gracePeriodEndsAt) {
      return false;
    }
    return new Date() < state.gracePeriodEndsAt;
  }

  /**
   * Get the rotation history, most recent first.
   */
  async getRotationHistory(limit = 10): Promise<TeeKeyRotationLog[]> {
    return this.rotationLogRepository.find({
      order: { createdAt: 'DESC' },
      take: limit,
    });
  }

  /**
   * Clear the previous epoch fields after the grace period has ended.
   * Called by the scheduler after the grace period expires.
   */
  async deprecatePreviousEpoch(): Promise<void> {
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
}
