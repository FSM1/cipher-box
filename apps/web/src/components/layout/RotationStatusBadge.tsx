import { useRotationStore, type RotationStatus } from '../../stores/rotation.store';

const labels: Partial<Record<RotationStatus, string>> = {
  'root-cut': 'Revoking access…',
  'tail-walk': 'Finishing revocation…',
  resuming: 'Resuming revocation…',
};

/**
 * Non-interactive rotation status pill mounted in AppHeader's .header-right
 * (D-02/D-03). Renders nothing when idle. Uses role="status" with a polite
 * live-region setting only, since this is informational, not an error. No
 * per-item/subtree detail is exposed (T-68-41): only a coarse phase label.
 */
export function RotationStatusBadge() {
  const status = useRotationStore((s) => s.status);

  if (status === 'idle') return null;

  const isRootCut = status === 'root-cut';
  const modifierClass = isRootCut
    ? 'rotation-status-badge--active'
    : 'rotation-status-badge--background';

  return (
    <div className={`rotation-status-badge ${modifierClass}`} role="status" aria-live="polite">
      {isRootCut && <span className="rotation-status-badge__spinner" aria-hidden="true" />}
      <span>{labels[status]}</span>
    </div>
  );
}
