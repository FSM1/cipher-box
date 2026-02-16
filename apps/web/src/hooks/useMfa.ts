import { useCallback } from 'react';
import {
  COREKIT_STATUS,
  generateFactorKey,
  keyToMnemonic,
  mnemonicToKey,
  TssShareType,
  FactorKeyTypeShareDescription,
  factorKeyCurve,
} from '@web3auth/mpc-core-kit';
import { Point } from '@tkey/common-types';
import BN from 'bn.js';
import { useCoreKit } from '../lib/web3auth/core-kit-provider';
import { useMfaStore } from '../stores/mfa.store';

export type FactorInfo = {
  factorPubHex: string;
  description: string;
  type: string;
  /** Additional metadata set during createFactor (e.g. deviceId, browserName) */
  additionalMetadata?: Record<string, string>;
};

export function useMfa() {
  const { coreKit, syncStatus } = useCoreKit();

  const isMfaEnabled = useMfaStore((s) => s.isMfaEnabled);
  const isEnrolling = useMfaStore((s) => s.isEnrolling);
  const factorCount = useMfaStore((s) => s.factorCount);
  const threshold = useMfaStore((s) => s.threshold);

  /**
   * Check MFA status from Core Kit key details.
   * MFA is enabled when totalFactors >= 2.
   */
  const checkMfaStatus = useCallback((): {
    isMfaEnabled: boolean;
    totalFactors: number;
    threshold: number;
  } => {
    if (!coreKit || coreKit.status !== COREKIT_STATUS.LOGGED_IN) {
      return { isMfaEnabled: false, totalFactors: 0, threshold: 0 };
    }
    try {
      const details = coreKit.getKeyDetails();
      const enabled = details.totalFactors >= 2;
      useMfaStore.getState().setMfaEnabled(enabled);
      useMfaStore.getState().setFactorDetails(details.totalFactors, details.threshold);
      return {
        isMfaEnabled: enabled,
        totalFactors: details.totalFactors,
        threshold: details.threshold,
      };
    } catch {
      return { isMfaEnabled: false, totalFactors: 0, threshold: 0 };
    }
  }, [coreKit]);

  /**
   * Enable MFA. Returns 24-word recovery mnemonic.
   * CRITICAL: commitChanges() must be called before enableMFA() in manualSync mode.
   */
  const enableMfa = useCallback(async (): Promise<string> => {
    if (!coreKit) throw new Error('Core Kit not initialized');
    if (coreKit.status !== COREKIT_STATUS.LOGGED_IN) {
      throw new Error('Must be logged in to enable MFA');
    }

    const store = useMfaStore.getState();
    if (store.isMfaEnabled) {
      throw new Error('MFA is already enabled');
    }

    useMfaStore.getState().setEnrolling(true);
    try {
      // Commit any pending changes first (CRITICAL for manualSync mode -- Pitfall 1)
      await coreKit.commitChanges();

      // Capture TSS public key BEFORE enableMFA for stability verification (MFA-04)
      const preMfaTssPub = coreKit.getKeyDetails().tssPubKey;

      // enableMFA creates device factor + recovery factor atomically
      const backupFactorKeyHex = await coreKit.enableMFA({});

      // Commit the MFA changes
      await coreKit.commitChanges();

      // Defensive check: verify TSS public key unchanged after MFA enrollment (MFA-04)
      const postMfaTssPub = coreKit.getKeyDetails().tssPubKey;
      if (preMfaTssPub?.x && preMfaTssPub?.y && postMfaTssPub?.x && postMfaTssPub?.y) {
        const preX = preMfaTssPub.x.toString('hex');
        const preY = preMfaTssPub.y.toString('hex');
        const postX = postMfaTssPub.x.toString('hex');
        const postY = postMfaTssPub.y.toString('hex');
        if (preX !== postX || preY !== postY) {
          throw new Error(
            'MFA enrollment failed: TSS public key changed. Your keypair identity is no longer stable. Please contact support.'
          );
        }
      }

      // Convert to 24-word mnemonic for user display
      const mnemonic = keyToMnemonic(backupFactorKeyHex);

      // Update store with new key details
      const details = coreKit.getKeyDetails();
      useMfaStore.getState().setMfaEnabled(true);
      useMfaStore.getState().setFactorDetails(details.totalFactors, details.threshold);

      return mnemonic;
    } finally {
      useMfaStore.getState().setEnrolling(false);
    }
  }, [coreKit]);

  /**
   * Input a factor key (hex string) to complete REQUIRED_SHARE login.
   * Used for both recovery and cross-device approval flows.
   */
  const inputFactorKey = useCallback(
    async (factorKeyHex: string): Promise<void> => {
      if (!coreKit) throw new Error('Core Kit not initialized');
      const factorKey = new BN(factorKeyHex, 'hex');
      await coreKit.inputFactorKey(factorKey);
      syncStatus();
    },
    [coreKit, syncStatus]
  );

  /**
   * Recover with a 24-word mnemonic phrase.
   * After recovery, creates a device factor for the new device.
   */
  const recoverWithMnemonic = useCallback(
    async (mnemonic: string): Promise<void> => {
      if (!coreKit) throw new Error('Core Kit not initialized');

      // Convert mnemonic to factor key hex
      const factorKeyHex = mnemonicToKey(mnemonic.trim().toLowerCase());
      await inputFactorKey(factorKeyHex);

      // Create a device factor for this new device
      const newDeviceFactor = generateFactorKey();
      await coreKit.createFactor({
        shareType: TssShareType.DEVICE,
        factorKey: newDeviceFactor.private,
        shareDescription: FactorKeyTypeShareDescription.DeviceShare,
      });
      await coreKit.setDeviceFactor(newDeviceFactor.private);
      await coreKit.commitChanges();
    },
    [coreKit, inputFactorKey]
  );

  /**
   * Get all factors with their descriptions.
   * shareDescriptions is Record<string, string[]> where keys are factor pub hex.
   */
  const getFactors = useCallback((): FactorInfo[] => {
    if (!coreKit || coreKit.status !== COREKIT_STATUS.LOGGED_IN) return [];
    try {
      const details = coreKit.getKeyDetails();
      const factors: FactorInfo[] = [];

      for (const [factorPubHex, descriptions] of Object.entries(details.shareDescriptions)) {
        for (const descJson of descriptions) {
          try {
            const parsed = JSON.parse(descJson) as {
              module?: string;
              additionalMetadata?: Record<string, string>;
            };
            factors.push({
              factorPubHex,
              description: parsed.module || 'unknown',
              type: parsed.module || 'unknown',
              additionalMetadata: parsed.additionalMetadata,
            });
          } catch {
            factors.push({
              factorPubHex,
              description: 'unknown',
              type: 'unknown',
            });
          }
        }
      }

      return factors;
    } catch {
      return [];
    }
  }, [coreKit]);

  /**
   * Delete a factor by its public key hex.
   * Cannot delete the currently active factor or the last remaining factor.
   */
  const deleteFactor = useCallback(
    async (factorPubHex: string): Promise<void> => {
      if (!coreKit) throw new Error('Core Kit not initialized');
      const factorPub = Point.fromSEC1(factorKeyCurve, factorPubHex);
      await coreKit.deleteFactor(factorPub);
      await coreKit.commitChanges();
    },
    [coreKit]
  );

  /**
   * Get the current active factor key and share type.
   */
  const getCurrentFactorKey = useCallback((): {
    factorKey: BN;
    shareType: TssShareType;
  } | null => {
    if (!coreKit || coreKit.status !== COREKIT_STATUS.LOGGED_IN) return null;
    try {
      return coreKit.getCurrentFactorKey();
    } catch {
      return null;
    }
  }, [coreKit]);

  /**
   * Regenerate the recovery phrase.
   * Deletes the old recovery factor and creates a new one.
   * Returns the new 24-word mnemonic.
   */
  const regenerateRecoveryPhrase = useCallback(async (): Promise<string> => {
    if (!coreKit) throw new Error('Core Kit not initialized');
    if (coreKit.status !== COREKIT_STATUS.LOGGED_IN) {
      throw new Error('Must be logged in to regenerate recovery phrase');
    }

    // Find the existing recovery (seedPhrase) factor
    const factors = getFactors();
    const recoveryFactor = factors.find((f) => f.type === FactorKeyTypeShareDescription.SeedPhrase);

    if (recoveryFactor) {
      // Delete old recovery factor
      const factorPub = Point.fromSEC1(factorKeyCurve, recoveryFactor.factorPubHex);
      await coreKit.deleteFactor(factorPub);
    }

    // Generate new recovery factor
    const newRecovery = generateFactorKey();
    await coreKit.createFactor({
      shareType: TssShareType.RECOVERY,
      factorKey: newRecovery.private,
      shareDescription: FactorKeyTypeShareDescription.SeedPhrase,
    });
    await coreKit.commitChanges();

    // Convert the new factor key to mnemonic
    // Zero-pad to 64 hex chars (32 bytes)
    const factorKeyHex = newRecovery.private.toString('hex').padStart(64, '0');
    return keyToMnemonic(factorKeyHex);
  }, [coreKit, getFactors]);

  return {
    // State from store
    isMfaEnabled,
    isEnrolling,
    factorCount,
    threshold,

    // Operations
    checkMfaStatus,
    enableMfa,
    inputFactorKey,
    recoverWithMnemonic,
    getFactors,
    deleteFactor,
    getCurrentFactorKey,
    regenerateRecoveryPhrase,
  };
}
