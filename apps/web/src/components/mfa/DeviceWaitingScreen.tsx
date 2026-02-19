import { useCallback, useEffect, useRef, useState } from 'react';
import { useDeviceApproval, type ApprovalStatus } from '../../hooks/useDeviceApproval';

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

  const [countdown, setCountdown] = useState(APPROVAL_TTL_MS);
  const startTimeRef = useRef<number>(Date.now());
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Start the approval request on mount
  useEffect(() => {
    startTimeRef.current = Date.now();
    requestApproval();

    // Countdown timer
    countdownRef.current = setInterval(() => {
      const elapsed = Date.now() - startTimeRef.current;
      const remaining = Math.max(0, APPROVAL_TTL_MS - elapsed);
      setCountdown(remaining);
    }, 1000);

    return () => {
      if (countdownRef.current) {
        clearInterval(countdownRef.current);
      }
      // Cancel request on unmount
      cancelRequest();
    };
  }, []);

  // Auto-complete when approval succeeds
  useEffect(() => {
    if (approvalStatus === 'approved') {
      onApprovalComplete();
    }
  }, [approvalStatus, onApprovalComplete]);

  const handleRetry = useCallback(() => {
    startTimeRef.current = Date.now();
    setCountdown(APPROVAL_TTL_MS);
    requestApproval();
  }, [requestApproval]);

  const minutes = Math.floor(countdown / 60000);
  const seconds = Math.floor((countdown % 60000) / 1000);
  const timeDisplay = `${minutes}:${seconds.toString().padStart(2, '0')}`;
  const isWarning = countdown <= COUNTDOWN_WARNING_MS && countdown > 0;

  return (
    <div className="device-waiting">
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
        <div className="device-waiting-status-message device-waiting-denied">
          Request was denied by another device.
        </div>
        <div className="device-waiting-actions">
          <button type="button" className="device-waiting-btn" onClick={handleRetry}>
            --retry
          </button>
          <button type="button" className="device-waiting-link" onClick={onRecoveryFallback}>
            use recovery phrase instead
          </button>
        </div>
      </div>
    );
  }

  if (status === 'expired') {
    return (
      <div className="device-waiting-content">
        <div className="device-waiting-status-message device-waiting-expired">
          Request expired. No device responded within the time limit.
        </div>
        <div className="device-waiting-actions">
          <button type="button" className="device-waiting-btn" onClick={handleRetry}>
            --retry
          </button>
          <button type="button" className="device-waiting-link" onClick={onRecoveryFallback}>
            use recovery phrase instead
          </button>
        </div>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="device-waiting-content">
        <div className="device-waiting-status-message device-waiting-error">
          {approvalError || 'An error occurred.'}
        </div>
        <div className="device-waiting-actions">
          <button type="button" className="device-waiting-btn" onClick={handleRetry}>
            --retry
          </button>
          <button type="button" className="device-waiting-link" onClick={onRecoveryFallback}>
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
      >
        {countdown > 0 ? timeDisplay : 'expired'}
      </div>
      <button type="button" className="device-waiting-link" onClick={onRecoveryFallback}>
        use recovery phrase instead
      </button>
    </div>
  );
}
