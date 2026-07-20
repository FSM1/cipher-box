/**
 * `CredentialStore` — refresh-token persistence.
 *
 * Web is a **no-op** (blueprint/web-client.md seam table): the rotating refresh
 * token rides the HTTP-only cookie on the {@link HttpSeam} instead, so there is
 * nothing for this seam to persist. The no-op is contractual — `load` after
 * `store` may return `None`, and `clear` always results in `None`.
 */

import type { CredentialStoreSeam } from './types.js';

export class NoopCredentialStore implements CredentialStoreSeam {
  async storeRefreshToken(_refreshToken: Uint8Array): Promise<void> {
    // Intentionally discarded — the HTTP-only cookie is the web refresh vehicle.
  }

  async loadRefreshToken(): Promise<Uint8Array | null> {
    return null;
  }

  async clearRefreshToken(): Promise<void> {
    // Nothing persisted, nothing to clear.
  }
}
