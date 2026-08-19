/**
 * Web's re-export capability over the shared secret handoff. The export and the
 * transfer to `start(secret)` are host-agnostic and live in `@cipherbox/login`;
 * what is web-only is this: a tab promoted to leader re-exports the secret from
 * its own Core Kit session (blueprint/web-client.md "Engine hosting and tab
 * leadership").
 */

import { exportLoginSecret, type LoginSecretExporter } from '@cipherbox/login';
import type { LoginSecret, SecretSource } from '@cipherbox/client';

/** The `SecretSource` a failover promotion re-exports through. */
export class LoginSecretSource implements SecretSource {
  private exporter: LoginSecretExporter | null = null;

  /** Registers the logged-in Core Kit instance; `null` on logout. */
  use(exporter: LoginSecretExporter | null): void {
    this.exporter = exporter;
  }

  async provideSecret(): Promise<LoginSecret> {
    const exporter = this.exporter;
    if (!exporter) throw new Error('no login session to re-export the secret from');
    const accountId = exporter.accountId();
    return { secret: await exportLoginSecret(exporter), accountId };
  }
}
