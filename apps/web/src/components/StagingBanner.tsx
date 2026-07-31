import { environment } from '../engine/config';

/** Warns that a staging deployment makes no data-safety guarantee. */
export function StagingBanner() {
  if (environment(import.meta.env) !== 'staging') return null;

  return (
    <div role="banner" data-testid="staging-banner" className="staging-banner">
      <span className="staging-banner-title">⚠ Staging environment ⚠</span>
      <span className="staging-banner-detail">
        // This is a staging instance for testing purposes only. No guarantees are made regarding
        data safety or security.
      </span>
    </div>
  );
}
