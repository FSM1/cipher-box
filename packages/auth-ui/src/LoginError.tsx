import type { ReactNode } from 'react';

/** The one error banner a login page and its methods both render. */
export function LoginError({ message }: { message: ReactNode }) {
  return (
    <div className="login-error" role="alert" aria-live="polite">
      {message}
    </div>
  );
}
