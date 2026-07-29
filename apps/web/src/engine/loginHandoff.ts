/**
 * The Web3Auth Core Kit → engine secret handoff (blueprint/web-client.md "Login
 * and identity"). Core Kit runs on the UI thread and exports the login secret;
 * this module hands it to the engine **once**, transferred, and holds nothing.
 * Every derivation — identity key, encryption subkey, pointer chain, vault
 * entry — happens in the engine, from those bytes.
 */

import { fromHex, type EngineClient, type SecretSource } from '@cipherbox/client';

/** The Core Kit surface this handoff drives, as a seam. */
export interface LoginSecretExporter {
  _UNSAFE_exportTssKey(): Promise<string>;
}

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
  if (decoded.length === 0) throw new Error('login secret export is empty');

  const secret = new ArrayBuffer(decoded.length);
  new Uint8Array(secret).set(decoded);
  decoded.fill(0);
  return secret;
}

/**
 * Cold-starts the engine with the login secret. `start` transfers the buffer,
 * so the worker is its terminal owner from the `postMessage` onward; the
 * `finally` scrubs only the case where the transfer never happened.
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

/**
 * Re-exports the secret when this tab is promoted to leader mid-session. Keys
 * never persist in JS, so the failover path goes back to the live Core Kit
 * session for them.
 */
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
