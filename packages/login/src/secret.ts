/**
 * The Core Kit → engine secret handoff. Core Kit runs on the host's UI thread
 * and exports the login secret; this module hands it to the facade once,
 * transferred, and holds nothing.
 */

/** The Core Kit surface this handoff drives, as a seam. */
export interface LoginSecretExporter {
  _UNSAFE_exportTssKey(): Promise<string>;
}

/**
 * The facade the login sequence starts, parameterised because the transport is
 * per host: a WASM worker on web, Tauri IPC on desktop.
 */
export interface LoginFacade {
  start(secret: ArrayBuffer): Promise<void>;
  logout(): Promise<void>;
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
 * Cold-starts the engine with the login secret. `start` can reject before it
 * delegates, so this frame stays the buffer's terminal owner until a transfer
 * detaches it (security rule 7).
 */
export async function handOffLoginSecret(
  facade: LoginFacade,
  exporter: LoginSecretExporter
): Promise<void> {
  const secret = await exportLoginSecret(exporter);
  try {
    await facade.start(secret);
  } finally {
    if (secret.byteLength > 0) new Uint8Array(secret).fill(0);
  }
}

/**
 * Decodes secret-bearing hex, so the bytes already decoded must not survive the
 * throw (blueprint/core.md: scrub on error paths too).
 */
function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new TypeError('odd-length hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const high = nibble(hex.charCodeAt(i * 2));
    const low = nibble(hex.charCodeAt(i * 2 + 1));
    if (high < 0 || low < 0) {
      out.fill(0, 0, i);
      throw new TypeError('non-hex character');
    }
    out[i] = (high << 4) | low;
  }
  return out;
}

function nibble(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;
  return -1;
}
