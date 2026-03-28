/**
 * Error boundary fallback UI — shown when an unhandled React render error occurs.
 * Pure presentational component with no hooks or state, so it works even when
 * React state is corrupted. Follows CipherBox's terminal/cipher aesthetic.
 */
export function ErrorFallback() {
  return (
    <div className="error-fallback">
      <div className="error-fallback__container">
        <div className="error-fallback__icon">{'// ERROR'}</div>
        <h1 className="error-fallback__title">Something went wrong</h1>
        <p className="error-fallback__message">
          An unexpected error occurred. Your encrypted data is safe — this is a display issue only.
        </p>
        <button
          className="error-fallback__reload"
          onClick={() => window.location.reload()}
          type="button"
        >
          {'> RELOAD'}
        </button>
      </div>
    </div>
  );
}
