import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useDeviceApproval } from '../../hooks/useDeviceApproval';
import { useMfa } from '../../hooks/useMfa';
import { useAuth } from '../../hooks/useAuth';
import { useCoreKit } from '../../lib/web3auth/core-kit-provider';

/**
 * Modal overlay shown on an existing (already logged-in) device when
 * pending approval requests exist. Displays device details, a warning,
 * and --approve / --deny buttons.
 *
 * Mounted in AppShell so it appears regardless of which page the user is on.
 * Only polls and renders when authenticated, MFA is enabled, and the user
 * is NOT in REQUIRED_SHARE state themselves (they'd be the requester).
 */
export function DeviceApprovalModal() {
  const { isAuthenticated, isRequiredShare } = useAuth();
  const { isRequiredShare: coreKitRequiredShare } = useCoreKit();
  const { checkMfaStatus, isMfaEnabled } = useMfa();
  const { pollPendingRequests, stopApproverPolling, approveRequest, denyRequest, pendingRequests } =
    useDeviceApproval();

  const [isResponding, setIsResponding] = useState(false);
  const [respondError, setRespondError] = useState<string | null>(null);
  const checkedRef = useRef(false);

  // Check MFA status on mount (once)
  useEffect(() => {
    if (isAuthenticated && !checkedRef.current) {
      checkedRef.current = true;
      checkMfaStatus();
    }
  }, [isAuthenticated, checkMfaStatus]);

  // Start/stop polling based on auth + MFA state
  useEffect(() => {
    const shouldPoll = isAuthenticated && isMfaEnabled && !isRequiredShare && !coreKitRequiredShare;

    if (shouldPoll) {
      pollPendingRequests();
    } else {
      stopApproverPolling();
    }

    return () => {
      stopApproverPolling();
    };
  }, [
    isAuthenticated,
    isMfaEnabled,
    isRequiredShare,
    coreKitRequiredShare,
    pollPendingRequests,
    stopApproverPolling,
  ]);

  // Show one request at a time (queue)
  const currentRequest = useMemo(
    () => (pendingRequests.length > 0 ? pendingRequests[0] : null),
    [pendingRequests]
  );

  const handleApprove = useCallback(async () => {
    if (!currentRequest) return;
    setIsResponding(true);
    setRespondError(null);
    try {
      await approveRequest(currentRequest.requestId, currentRequest.ephemeralPublicKey);
    } catch (err) {
      setRespondError(err instanceof Error ? err.message : 'Failed to approve');
    } finally {
      setIsResponding(false);
    }
  }, [currentRequest, approveRequest]);

  const handleDeny = useCallback(async () => {
    if (!currentRequest) return;
    setIsResponding(true);
    setRespondError(null);
    try {
      await denyRequest(currentRequest.requestId);
    } catch (err) {
      setRespondError(err instanceof Error ? err.message : 'Failed to deny');
    } finally {
      setIsResponding(false);
    }
  }, [currentRequest, denyRequest]);

  // Don't render if no pending requests
  if (!currentRequest) return null;

  const expiresAt = new Date(currentRequest.expiresAt).getTime();
  const createdAt = new Date(currentRequest.createdAt).getTime();

  return (
    <div
      className="device-approval-backdrop"
      role="dialog"
      aria-modal="true"
      aria-label="Device approval request"
    >
      <div className="device-approval-modal">
        <div className="device-approval-header">
          <h2 className="device-approval-title">Device Approval Request</h2>
        </div>

        <div className="device-approval-body">
          <div className="device-approval-details">
            <div className="device-approval-detail-row">
              <span className="device-approval-detail-label">device</span>
              <span className="device-approval-detail-value">{currentRequest.deviceName}</span>
            </div>
            <div className="device-approval-detail-row">
              <span className="device-approval-detail-label">requested</span>
              <span className="device-approval-detail-value">{formatTimeAgo(createdAt)}</span>
            </div>
            <div className="device-approval-detail-row">
              <span className="device-approval-detail-label">expires</span>
              <CountdownValue expiresAt={expiresAt} />
            </div>
          </div>

          <div className="device-approval-warning">
            Only approve if YOU are trying to log in on another device.
          </div>

          {respondError && (
            <div className="device-approval-warning" role="alert">
              {respondError}
            </div>
          )}

          {pendingRequests.length > 1 && (
            <div style={{ fontSize: '10px', color: 'var(--color-text-dim)' }}>
              {`+${pendingRequests.length - 1} more pending request${pendingRequests.length > 2 ? 's' : ''}`}
            </div>
          )}
        </div>

        <div className="device-approval-actions">
          <button
            type="button"
            className="device-approval-btn-deny"
            onClick={handleDeny}
            disabled={isResponding}
          >
            --deny
          </button>
          <button
            type="button"
            className="device-approval-btn-approve"
            onClick={handleApprove}
            disabled={isResponding}
          >
            {isResponding ? 'approving...' : '--approve'}
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * Live countdown to expiry time.
 */
function CountdownValue({ expiresAt }: { expiresAt: number }) {
  const [remaining, setRemaining] = useState(() => Math.max(0, expiresAt - Date.now()));
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    intervalRef.current = setInterval(() => {
      setRemaining(Math.max(0, expiresAt - Date.now()));
    }, 1000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [expiresAt]);

  const minutes = Math.floor(remaining / 60000);
  const seconds = Math.floor((remaining % 60000) / 1000);
  const isWarning = remaining <= 3 * 60 * 1000 && remaining > 0;

  return (
    <span
      className={`device-approval-detail-value device-approval-countdown ${isWarning ? 'warning' : ''}`}
    >
      {remaining > 0 ? `${minutes}:${seconds.toString().padStart(2, '0')}` : 'expired'}
    </span>
  );
}

/**
 * Format a timestamp as a relative time string (e.g. "just now", "2m ago").
 */
function formatTimeAgo(timestampMs: number): string {
  const diff = Date.now() - timestampMs;
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  return `${Math.floor(diff / 3_600_000)}h ago`;
}
