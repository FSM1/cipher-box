/**
 * The e2e seam (blueprint/testing.md "E2E"): read-only taps over the facade's
 * snapshot and event stream, plus the cold start the suite drives in place of
 * an interactive Core Kit login.
 *
 * Gated on `VITE_E2E_HOOK` rather than on `DEV`, because the suite runs against
 * the production static build — the artifact a `DEV` gate would exclude the
 * hook from is the very one under test.
 */

import { fromHex, toHex } from '@cipherbox/client';
import { handOffLoginSecret } from '@cipherbox/login';
import type { SecretRearm } from '@cipherbox/login';
import type { EngineClient, EventDescriptor, SnapshotDescriptor } from '@cipherbox/client';

/**
 * A structured-clone-safe projection of an engine descriptor: `Uint8Array`
 * becomes hex and `bigint` becomes a decimal string, neither of which survives
 * the Playwright evaluation boundary as itself.
 */
export type Plain<T> = T extends Uint8Array
  ? string
  : T extends bigint
    ? string
    : T extends readonly (infer U)[]
      ? Plain<U>[]
      : T extends object
        ? { [K in keyof T]: Plain<T[K]> }
        : T;

export interface IntrospectedView {
  view: Plain<SnapshotDescriptor>;
  /** The view is the latest version and the queue holds nothing for it. */
  settled: boolean;
}

export interface EngineIntrospection {
  /** Cold-starts the engine from a 32-byte hex login secret. */
  signIn(loginSecretHex: string, accountId: string): Promise<void>;
  /** The engine's view of the vault root. */
  snapshot(): Promise<IntrospectedView>;
  /** One node's plaintext as the engine reads it back, hex like every other tap. */
  download(nodeHex: string): Promise<string>;
  /** Every engine event this tab has seen, in emission order. */
  events(): Plain<EventDescriptor>[];
  /**
   * How many times this tab has re-exported its login secret for a promotion.
   * Counted for the tab, not the client, so a rebuilt one cannot reset it.
   */
  reExports(): number;
}

/** Survives the client rebuild a session end drives, which is the point. */
let reExports = 0;

declare global {
  interface Window {
    __CIPHERBOX_ENGINE__?: EngineIntrospection;
  }
}

/**
 * Publishes the taps for `client` on `window`, and returns it so a host can
 * wrap its client factory. A no-op outside an e2e build.
 */
export function installIntrospection(client: EngineClient, secrets?: SecretRearm): EngineClient {
  if (import.meta.env.VITE_E2E_HOOK !== 'true') return client;

  const seen: Plain<EventDescriptor>[] = [];
  client.facade.subscribe((event) => {
    seen.push(plain(event) as Plain<EventDescriptor>);
  });

  window.__CIPHERBOX_ENGINE__ = {
    signIn(loginSecretHex, accountId) {
      const source = { accountId: () => accountId };
      // Armed as the real flow arms it (`createLoginFlow`), so a promotion in
      // this tab re-exports rather than failing for want of a source the suite
      // never installed. Two exporters over the one secret: only a promotion's
      // export counts, so the cold start below leaves the tally alone.
      secrets?.use({
        ...source,
        _UNSAFE_exportTssKey: () => {
          reExports += 1;
          return Promise.resolve(loginSecretHex);
        },
      });
      return handOffLoginSecret(client.facade, {
        ...source,
        _UNSAFE_exportTssKey: () => Promise.resolve(loginSecretHex),
      });
    },
    async snapshot() {
      const view = await client.facade.snapshot(null);
      return { view: plain(view) as Plain<SnapshotDescriptor>, settled: settled(view) };
    },
    async download(nodeHex) {
      return toHex(new Uint8Array(await client.facade.download(fromHex(nodeHex))));
    },
    events: () => seen,
    reExports: () => reExports,
  };
  return client;
}

/** The deterministic wait the suite polls in place of a sleep. */
function settled(view: SnapshotDescriptor): boolean {
  return (
    view.staleness === 'fresh' &&
    view.blocked === null &&
    view.children.every((child) => child.pending === 'none')
  );
}

function plain(value: unknown): unknown {
  if (value instanceof Uint8Array) return toHex(value);
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(plain);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, plain(item)]));
  }
  return value;
}
