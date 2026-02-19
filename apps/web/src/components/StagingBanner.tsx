interface StagingBannerProps {
  variant: 'login' | 'compact';
}

/**
 * Staging environment warning banner.
 * Renders only when VITE_ENVIRONMENT=staging, returns null otherwise.
 * Two variants: 'login' (fixed overlay on login page) and 'compact' (flow element in AppShell).
 */
export function StagingBanner({ variant }: StagingBannerProps) {
  if (import.meta.env.VITE_ENVIRONMENT !== 'staging') {
    return null;
  }

  if (variant === 'login') {
    return (
      <div
        role="banner"
        data-testid="staging-banner"
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          width: '100%',
          zIndex: 1000,
          backgroundColor: '#3d1a00',
          borderBottom: '1px solid #FF6B00',
          padding: '10px 16px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '4px',
          boxSizing: 'border-box',
        }}
      >
        <span
          style={{
            fontFamily: 'var(--font-family-mono)',
            fontSize: '13px',
            fontWeight: 700,
            color: '#FF6B00',
            letterSpacing: '2px',
            textTransform: 'uppercase',
          }}
        >
          {'\u26A0'} STAGING ENVIRONMENT {'\u26A0'}
        </span>
        <span
          style={{
            fontFamily: 'var(--font-family-mono)',
            fontSize: '11px',
            fontWeight: 400,
            color: '#994400',
            textAlign: 'center',
          }}
        >
          {
            '// This is a staging instance for testing purposes only. No guarantees are made regarding data safety or security.'
          }
        </span>
      </div>
    );
  }

  // compact variant
  return (
    <div
      role="banner"
      data-testid="staging-banner"
      style={{
        width: '100%',
        height: '36px',
        backgroundColor: '#3d1a00',
        borderBottom: '1px solid #FF6B00',
        display: 'flex',
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        boxSizing: 'border-box',
        flexShrink: 0,
      }}
    >
      <span
        style={{
          fontFamily: 'var(--font-family-mono)',
          fontSize: '11px',
          fontWeight: 700,
          color: '#FF6B00',
          letterSpacing: '1px',
        }}
      >
        {'\u26A0'} STAGING | Testing only {'\u2014'} data may be wiped without notice {'\u26A0'}
      </span>
    </div>
  );
}
