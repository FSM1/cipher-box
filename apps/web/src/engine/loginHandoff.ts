/**
 * The Web3Auth Core Kit → engine secret handoff (blueprint/web-client.md "Login
 * and identity"). Core Kit runs on the UI thread and exports the login secret;
 * this module hands it to the engine once, transferred, and holds nothing.
 */

import { fromHex, type EngineClient, type SecretSource } from '@cipherbox/client';

/** The Core Kit surface this handoff drives, as a seam. */
export interface LoginSecretExporter {
  _UNSAFE_exportTssKey(): Promise<string>;
}

/** The secp256k1 scalar length `crates/engine/src/session.rs` requires. */
const LOGIN_SECRET_LEN = 32;

/**
 * Exports the login secret as a buffer the caller owns and must transfer or
 * zero. Core Kit yields hex in an immutable JS string that cannot be scrubbed;
 * the decoded buffer is the only copy whose lifetime we control.
 */
export async function exportLoginSecret(exporter: LoginSecretExporter): Promise<ArrayBuffer> {
  const exported = await exporter._UNSAFE_exportTssKey();
  const hex = exported.startsWith('0x') ? exported.slice(2) : exported;

  let decoded: Uint8Array;
  try {
    decoded = fromHex(hex);
  } catch {
    // Never re-raise the decoder's message: its input is the secret.
    throw new Error('login secret export is not hex');
  }
  if (decoded.length !== LOGIN_SECRET_LEN) {
    decoded.fill(0);
    throw new Error('login secret export is not a 32-byte scalar');
  }

  // Copy rather than hand over `decoded.buffer`: the transferred buffer must
  // hold the secret and nothing else, whatever the decoder allocated.
  const secret = new ArrayBuffer(decoded.length);
  new Uint8Array(secret).set(decoded);
  decoded.fill(0);
  return secret;
}

/**
 * Cold-starts the engine with the login secret. `EngineClient.start` can reject
 * before it delegates, so this frame stays the buffer's terminal owner until a
 * transfer detaches it (security rule 7).
 */
export async function handOffLoginSecret(
  client: EngineClient,
  exporter: LoginSecretExporter
): Promise<void> {
  const secret = await exportLoginSecret(exporter);
  try {
    await client.facade.start(secret);
  } finally {
    if (secret.byteLength > 0) new Uint8Array(secret).fill(0);
  }
}

/** The `SecretSource` a failover promotion re-exports through. */
export class LoginSecretSource implements SecretSource {
  private exporter: LoginSecretExporter | null = null;

  /** Registers the logged-in Core Kit instance; `null` on logout. */
  use(exporter: LoginSecretExporter | null): void {
    this.exporter = exporter;
  }

  provideSecret(): Promise<ArrayBuffer> {
    const exporter = this.exporter;
    if (!exporter)
      return Promise.reject(new Error('no login session to re-export the secret from'));
    return exportLoginSecret(exporter);
  }
}
