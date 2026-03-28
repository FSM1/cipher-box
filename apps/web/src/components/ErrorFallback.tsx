/** Pure presentational — no hooks/state so it works even when React state is corrupted. */
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
