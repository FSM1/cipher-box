import { useCallback, useEffect, useRef, useState } from 'react';
import { useDeviceApproval, type ApprovalStatus } from '../../hooks/useDeviceApproval';
import { useAuthStore } from '../../stores/auth.store';

type DeviceWaitingScreenProps = {
  onRecoveryFallback: () => void;
  onApprovalComplete: () => void;
};

const APPROVAL_TTL_MS = 5 * 60 * 1000; // 5 minutes
const COUNTDOWN_WARNING_MS = 3 * 60 * 1000; // 3 minutes remaining

/**
 * Full-screen waiting component shown when a new device is in
 * REQUIRED_SHARE state. Creates a bulletin board approval request
 * and polls for a response from an existing device.
 *
 * Displays a spinner, countdown timer, and a fallback link to
 * use a recovery phrase instead.
 */
export function DeviceWaitingScreen({
  onRecoveryFallback,
  onApprovalComplete,
}: DeviceWaitingScreenProps) {
  const { requestApproval, cancelRequest, approvalStatus, approvalError } = useDeviceApproval();
  const accessToken = useAuthStore((s) => s.accessToken);

  const [countdown, setCountdown] = useState(APPROVAL_TTL_MS);
  const startTimeRef = useRef<number>(Date.now());
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const requestFiredRef = useRef(false);

  // Stable refs for requestApproval and cancelRequest to prevent the effect
  // from re-firing when their identity changes due to upstream dependency
  // cascades (useCallback chains through useDeviceApproval → useMfa →
  // useAuth → useCoreKit). Without refs, any Core Kit state update would
  // cause the effect to cancel the current approval request and create a
  // new one, leading to intermittent failures when the approver device
  // clicks approve on the now-cancelled request.
  // Same pattern as useAuth.ts (initializeOrLoadVaultRef / coreKitLogoutRef).
  const requestApprovalRef = useRef(requestApproval);
  requestApprovalRef.current = requestApproval;
  const cancelRequestRef = useRef(cancelRequest);
  cancelRequestRef.current = cancelRequest;

  // Start the approval request once the temp access token is available.
  // The token is obtained asynchronously in loginWithGoogle/Email/Wallet
  // AFTER syncStatus() sets isRequiredShare=true, so this component may
  // mount before the token is stored. We wait for it to avoid a 401.
  //
  // Cleanup is paired with setup for React StrictMode safety: in dev mode,
  // the simulated unmount cancels the request and resets the guard ref,
  // allowing the second mount to re-create a fresh request with a new
  // ephemeral keypair.
  useEffect(() => {
    if (!accessToken || requestFiredRef.current) return;
    requestFiredRef.current = true;

    // Clear any existing interval before starting a new one (defensive against retry re-trigger)
    if (countdownRef.current) {
      clearInterval(countdownRef.current);
    }

    startTimeRef.current = Date.now();
    requestApprovalRef.current();

    // Countdown timer
    countdownRef.current = setInterval(() => {
      const elapsed = Date.now() - startTimeRef.current;
      const remaining = Math.max(0, APPROVAL_TTL_MS - elapsed);
      setCountdown(remaining);
    }, 1000);

    return () => {
      if (countdownRef.current) {
        clearInterval(countdownRef.current);
        countdownRef.current = null;
      }
      requestFiredRef.current = false;
      cancelRequestRef.current();
    };
  }, [accessToken]);

  // Auto-complete when approval succeeds
  useEffect(() => {
    if (approvalStatus === 'approved') {
      onApprovalComplete();
    }
  }, [approvalStatus, onApprovalComplete]);

  const handleRetry = useCallback(() => {
    requestFiredRef.current = false;
    startTimeRef.current = Date.now();
    setCountdown(APPROVAL_TTL_MS);
    requestApproval();
  }, [requestApproval]);

  const minutes = Math.floor(countdown / 60000);
  const seconds = Math.floor((countdown % 60000) / 1000);
  const timeDisplay = `${minutes}:${seconds.toString().padStart(2, '0')}`;
  const isWarning = countdown <= COUNTDOWN_WARNING_MS && countdown > 0;

  return (
    <div className="device-waiting" data-testid="device-waiting">
      <div className="device-waiting-card">
        <h2 className="device-waiting-title">{'// waiting for device approval'}</h2>

        {renderContent(approvalStatus, {
          timeDisplay,
          isWarning,
          countdown,
          approvalError,
          onRecoveryFallback,
          handleRetry,
        })}
      </div>
    </div>
  );
}

function renderContent(
  status: ApprovalStatus,
  props: {
    timeDisplay: string;
    isWarning: boolean;
    countdown: number;
    approvalError: string | null;
    onRecoveryFallback: () => void;
    handleRetry: () => void;
  }
) {
  const { timeDisplay, isWarning, countdown, approvalError, onRecoveryFallback, handleRetry } =
    props;

  if (status === 'denied') {
    return (
      <div className="device-waiting-content">
        <div
          className="device-waiting-status-message device-waiting-denied"
          data-testid="device-waiting-status"
        >
          Request was denied by another device.
        </div>
        <div className="device-waiting-actions">
          <button
            type="button"
            className="device-waiting-btn"
            onClick={handleRetry}
            data-testid="device-waiting-retry"
          >
            --retry
          </button>
          <button
            type="button"
            className="device-waiting-link"
            onClick={onRecoveryFallback}
            data-testid="device-waiting-recovery-link"
          >
            use recovery phrase instead
          </button>
        </div>
      </div>
    );
  }

  if (status === 'expired') {
    return (
      <div className="device-waiting-content">
        <div
          className="device-waiting-status-message device-waiting-expired"
          data-testid="device-waiting-status"
        >
          Request expired. No device responded within the time limit.
        </div>
        <div className="device-waiting-actions">
          <button
            type="button"
            className="device-waiting-btn"
            onClick={handleRetry}
            data-testid="device-waiting-retry"
          >
            --retry
          </button>
          <button
            type="button"
            className="device-waiting-link"
            onClick={onRecoveryFallback}
            data-testid="device-waiting-recovery-link"
          >
            use recovery phrase instead
          </button>
        </div>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="device-waiting-content">
        <div
          className="device-waiting-status-message device-waiting-error"
          data-testid="device-waiting-status"
        >
          {approvalError || 'An error occurred.'}
        </div>
        <div className="device-waiting-actions">
          <button
            type="button"
            className="device-waiting-btn"
            onClick={handleRetry}
            data-testid="device-waiting-retry"
          >
            --retry
          </button>
          <button
            type="button"
            className="device-waiting-link"
            onClick={onRecoveryFallback}
            data-testid="device-waiting-recovery-link"
          >
            use recovery phrase instead
          </button>
        </div>
      </div>
    );
  }

  if (status === 'completing') {
    return (
      <div className="device-waiting-content">
        <span className="device-waiting-spinner" aria-hidden="true" />
        <p className="device-waiting-text">Approval received. Completing login...</p>
      </div>
    );
  }

  // Default: requesting/pending
  return (
    <div className="device-waiting-content">
      <span className="device-waiting-spinner" aria-hidden="true" />
      <p className="device-waiting-text">
        Request sent to your other devices. Open CipherBox on an authorized device to approve this
        login.
      </p>
      <div
        className={`device-waiting-countdown ${isWarning ? 'warning' : ''}`}
        aria-label={`Time remaining: ${timeDisplay}`}
        data-testid="device-waiting-countdown"
      >
        {countdown > 0 ? timeDisplay : 'expired'}
      </div>
      <button
        type="button"
        className="device-waiting-link"
        onClick={onRecoveryFallback}
        data-testid="device-waiting-recovery-link"
      >
        use recovery phrase instead
      </button>
    </div>
  );
}
