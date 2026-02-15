/**
 * useDeviceApproval Hook
 *
 * Manages the full lifecycle for BOTH sides of the cross-device approval flow:
 *
 * **New device (requester):**
 * - Generate ephemeral secp256k1 keypair
 * - Create bulletin board request
 * - Poll for approval status
 * - On approval: ECIES-decrypt factor key, inputFactorKey, create device factor
 *
 * **Existing device (approver):**
 * - Poll for pending approval requests
 * - Approve: ECIES-encrypt current factor key with requester's ephemeral public key
 * - Deny: mark request as denied
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import * as secp256k1 from '@noble/secp256k1';
import {
  generateFactorKey,
  TssShareType,
  FactorKeyTypeShareDescription,
} from '@web3auth/mpc-core-kit';
import { wrapKey, unwrapKey, hexToBytes, bytesToHex } from '@cipherbox/crypto';
import { useCoreKit } from '../lib/web3auth/core-kit-provider';
import { useMfa } from './useMfa';
import { useVisibility } from './useVisibility';
import { useAuth } from './useAuth';
import { getOrCreateDeviceIdentity } from '../lib/device/identity';
import { detectDeviceInfo } from '../lib/device/info';
import {
  deviceApprovalApi,
  type ApprovalStatusResponse,
  type PendingApproval,
} from '../services/device-approval.service';

export type ApprovalStatus =
  | 'idle'
  | 'requesting'
  | 'pending'
  | 'approved'
  | 'denied'
  | 'expired'
  | 'completing'
  | 'error';

export function useDeviceApproval() {
  const { coreKit } = useCoreKit();
  const { inputFactorKey } = useMfa();
  const { completeRequiredShare } = useAuth();
  const isVisible = useVisibility();

  // --- New device (requester) state ---
  const [approvalStatus, setApprovalStatus] = useState<ApprovalStatus>('idle');
  const [approvalError, setApprovalError] = useState<string | null>(null);
  const requestIdRef = useRef<string | null>(null);
  const ephemeralPrivKeyRef = useRef<Uint8Array | null>(null);
  const requesterPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // --- Existing device (approver) state ---
  const [pendingRequests, setPendingRequests] = useState<PendingApproval[]>([]);
  const [isPollingPending, setIsPollingPending] = useState(false);
  const approverPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  /**
   * Zero-fill and clear ephemeral private key from memory.
   */
  const clearEphemeralKey = useCallback(() => {
    if (ephemeralPrivKeyRef.current) {
      ephemeralPrivKeyRef.current.fill(0);
      ephemeralPrivKeyRef.current = null;
    }
  }, []);

  /**
   * Stop requester polling.
   */
  const stopRequesterPolling = useCallback(() => {
    if (requesterPollRef.current) {
      clearInterval(requesterPollRef.current);
      requesterPollRef.current = null;
    }
  }, []);

  /**
   * Stop approver polling.
   */
  const stopApproverPolling = useCallback(() => {
    if (approverPollRef.current) {
      clearInterval(approverPollRef.current);
      approverPollRef.current = null;
    }
    setIsPollingPending(false);
  }, []);

  // =========================================================================
  // NEW DEVICE SIDE (REQUESTER)
  // =========================================================================

  /**
   * Handle a successful approval: decrypt factor key, input it, create device factor.
   */
  const handleApprovalSuccess = useCallback(
    async (encryptedFactorKeyHex: string) => {
      const ephPrivKey = ephemeralPrivKeyRef.current;
      if (!ephPrivKey) {
        throw new Error('Ephemeral private key not available');
      }
      if (!coreKit) {
        throw new Error('Core Kit not initialized');
      }

      setApprovalStatus('completing');

      try {
        // 1. ECIES-decrypt the factor key
        const encrypted = hexToBytes(encryptedFactorKeyHex);
        const factorKeyBytes = await unwrapKey(encrypted, ephPrivKey);
        const factorKeyHex = bytesToHex(factorKeyBytes);
        factorKeyBytes.fill(0); // Zero-fill decrypted key material after conversion

        // 2. Input the factor key to complete Core Kit login
        await inputFactorKey(factorKeyHex);

        // 3. Create device factor for this new device
        const newDeviceFactor = generateFactorKey();
        await coreKit.createFactor({
          shareType: TssShareType.DEVICE,
          factorKey: newDeviceFactor.private,
          shareDescription: FactorKeyTypeShareDescription.DeviceShare,
        });
        await coreKit.setDeviceFactor(newDeviceFactor.private);
        await coreKit.commitChanges();

        // 4. Clean up ephemeral key
        clearEphemeralKey();

        // 5. Complete the login flow
        await completeRequiredShare();

        setApprovalStatus('approved');
      } catch (err) {
        clearEphemeralKey();
        setApprovalError(err instanceof Error ? err.message : 'Failed to complete approval');
        setApprovalStatus('error');
        throw err;
      }
    },
    [coreKit, inputFactorKey, completeRequiredShare, clearEphemeralKey]
  );

  /**
   * Start polling for approval status (new device side).
   */
  const startRequesterPolling = useCallback(
    (requestId: string) => {
      stopRequesterPolling();

      const poll = async () => {
        try {
          const result: ApprovalStatusResponse = await deviceApprovalApi.getStatus(requestId);

          if (result.status === 'approved' && result.encryptedFactorKey) {
            stopRequesterPolling();
            await handleApprovalSuccess(result.encryptedFactorKey);
          } else if (result.status === 'denied') {
            stopRequesterPolling();
            clearEphemeralKey();
            setApprovalStatus('denied');
          } else if (result.status === 'expired') {
            stopRequesterPolling();
            clearEphemeralKey();
            setApprovalStatus('expired');
          }
          // 'pending' -> continue polling
        } catch {
          // Network error -- continue polling, don't crash
        }
      };

      requesterPollRef.current = setInterval(poll, 3000);
      // Fire immediately
      void poll();
    },
    [stopRequesterPolling, handleApprovalSuccess, clearEphemeralKey]
  );

  /**
   * Create an approval request on the bulletin board (new device side).
   * Generates an ephemeral keypair and starts polling.
   */
  const requestApproval = useCallback(async () => {
    setApprovalStatus('requesting');
    setApprovalError(null);

    try {
      // 1. Generate ephemeral secp256k1 keypair
      const ephemeral = secp256k1.keygen();
      ephemeralPrivKeyRef.current = ephemeral.secretKey;
      const ephemeralPubKeyHex = bytesToHex(ephemeral.publicKey);

      // 2. Get device identity
      const deviceIdentity = await getOrCreateDeviceIdentity();

      // 3. Get device name
      const deviceInfo = detectDeviceInfo();

      // 4. Create request on bulletin board
      const { requestId } = await deviceApprovalApi.createRequest({
        deviceId: deviceIdentity.deviceId,
        deviceName: deviceInfo.name,
        ephemeralPublicKey: ephemeralPubKeyHex,
      });

      requestIdRef.current = requestId;
      setApprovalStatus('pending');

      // 5. Start polling for response
      startRequesterPolling(requestId);
    } catch (err) {
      clearEphemeralKey();
      setApprovalError(err instanceof Error ? err.message : 'Failed to create approval request');
      setApprovalStatus('error');
    }
  }, [startRequesterPolling, clearEphemeralKey]);

  /**
   * Cancel the pending approval request (new device side).
   * Also called when recovery phrase is used instead (RESEARCH.md Pitfall 5).
   */
  const cancelRequest = useCallback(async () => {
    stopRequesterPolling();

    if (requestIdRef.current) {
      try {
        await deviceApprovalApi.cancel(requestIdRef.current);
      } catch {
        // Best-effort cleanup -- request may already be expired/cancelled
      }
      requestIdRef.current = null;
    }

    clearEphemeralKey();
    setApprovalStatus('idle');
  }, [stopRequesterPolling, clearEphemeralKey]);

  // =========================================================================
  // EXISTING DEVICE SIDE (APPROVER)
  // =========================================================================

  /**
   * Start polling for pending approval requests (existing device side).
   */
  const pollPendingRequests = useCallback(() => {
    if (isPollingPending) return;
    setIsPollingPending(true);

    const poll = async () => {
      try {
        const pending = await deviceApprovalApi.getPending();
        setPendingRequests(pending);
      } catch {
        // Network error -- continue polling
      }
    };

    // Poll every 5 seconds
    approverPollRef.current = setInterval(poll, 5000);
    // Fire immediately
    void poll();
  }, [isPollingPending]);

  /**
   * Approve a pending request: ECIES-encrypt current factor key with
   * the requester's ephemeral public key and send the response.
   */
  const approveRequest = useCallback(
    async (requestId: string, ephemeralPublicKeyHex: string) => {
      if (!coreKit) throw new Error('Core Kit not initialized');

      // 1. Get current factor key
      const factorKeyResult = coreKit.getCurrentFactorKey();
      if (!factorKeyResult?.factorKey) {
        throw new Error('No active factor key available to share');
      }
      const factorKeyHex = factorKeyResult.factorKey.toString('hex').padStart(64, '0');
      const factorKeyBytes = hexToBytes(factorKeyHex);

      // 2. ECIES-encrypt with the requester's ephemeral public key
      const ephemeralPubKey = hexToBytes(ephemeralPublicKeyHex);
      const encrypted = await wrapKey(factorKeyBytes, ephemeralPubKey);
      factorKeyBytes.fill(0); // Zero-fill factor key bytes after wrapping

      // 3. Get current device ID for tracking
      const deviceIdentity = await getOrCreateDeviceIdentity();

      // 4. Send response
      await deviceApprovalApi.respond(requestId, {
        action: 'approve',
        encryptedFactorKey: bytesToHex(encrypted),
        respondedByDeviceId: deviceIdentity.deviceId,
      });

      // 5. Remove from pending list
      setPendingRequests((prev) => prev.filter((r) => r.requestId !== requestId));
    },
    [coreKit]
  );

  /**
   * Deny a pending approval request.
   */
  const denyRequest = useCallback(async (requestId: string) => {
    // Get current device ID for tracking
    const deviceIdentity = await getOrCreateDeviceIdentity();

    await deviceApprovalApi.respond(requestId, {
      action: 'deny',
      respondedByDeviceId: deviceIdentity.deviceId,
    });

    // Remove from pending list
    setPendingRequests((prev) => prev.filter((r) => r.requestId !== requestId));
  }, []);

  // =========================================================================
  // VISIBILITY-BASED POLLING CONTROL (approver)
  // =========================================================================

  // Pause/resume approver polling based on tab visibility
  useEffect(() => {
    if (!isPollingPending) return;

    if (isVisible) {
      // Resume polling when tab becomes visible
      if (!approverPollRef.current) {
        const poll = async () => {
          try {
            const pending = await deviceApprovalApi.getPending();
            setPendingRequests(pending);
          } catch {
            // Network error -- continue polling
          }
        };
        approverPollRef.current = setInterval(poll, 5000);
        void poll();
      }
    } else {
      // Pause polling when tab is hidden
      if (approverPollRef.current) {
        clearInterval(approverPollRef.current);
        approverPollRef.current = null;
      }
    }
  }, [isVisible, isPollingPending]);

  // =========================================================================
  // CLEANUP ON UNMOUNT
  // =========================================================================

  useEffect(() => {
    return () => {
      stopRequesterPolling();
      stopApproverPolling();
      clearEphemeralKey();
    };
  }, [stopRequesterPolling, stopApproverPolling, clearEphemeralKey]);

  return {
    // Requester (new device)
    requestApproval,
    cancelRequest,
    approvalStatus,
    approvalError,

    // Approver (existing device)
    pollPendingRequests,
    stopApproverPolling,
    approveRequest,
    denyRequest,
    pendingRequests,
    isPolling: isPollingPending,
  };
}
