/**
 * The Core Kit → engine secret handoff. Core Kit runs on the host's UI thread
 * and exports the login secret; this module hands it to the facade once,
 * transferred, and holds nothing.
 */

/** A TSS public key point, as the Core Kit's key details carry it. */
export interface TssPublicPoint {
  x?: { toString(radix: 'hex'): string } | null;
  y?: { toString(radix: 'hex'): string } | null;
}

/**
 * Names an account by its TSS public key. The coordinates are separated, not
 * concatenated: hex drops leading zeroes, so two points could otherwise spell
 * one name.
 */
export function accountIdFromTssPoint(point: TssPublicPoint | undefined | null): string {
  if (!point?.x || !point.y) throw new Error('the account key could not be read on this device');
  return `${point.x.toString('hex')}-${point.y.toString('hex')}`;
}

/** The Core Kit surface this handoff drives, as a seam. */
export interface LoginSecretExporter {
  _UNSAFE_exportTssKey(): Promise<string>;
  /**
   * The signed-in account's stable, non-secret public identifier. A host that
   * keeps durable per-account state namespaces it by this; one that derives the
   * namespace below the facade ignores it.
   */
  accountId(): string;
}

/**
 * The facade the login sequence starts, parameterised because the transport is
 * per host: a WASM worker on web, Tauri IPC on desktop.
 */
export interface LoginFacade {
  /**
   * `identityToken` is the token of the exchange this start follows, which the
   * engine's login presents to bind the account to its subject (ADR 0058 D2).
   */
  start(secret: ArrayBuffer, accountId: string, identityToken?: string): Promise<void>;
  logout(): Promise<void>;
  /**
   * Erases the durable seams a logout keeps ("forget this device"). Optional
   * because a host may erase them off this seam entirely; the desktop shell's
   * own path is not landed, so its facade carries none and
   * [`LoginFlow.forgetDevice`] refuses there rather than passing a plain logout
   * off as an erase. What it answers with is the engine's to define; the login
   * flow reads only whether it refused.
   */
  forgetDevice?(): Promise<unknown>;
}

/**
 * The identity token a start may present, and the clock that decides whether
 * it still can. The deadline counts from `receivedAt` on the host's own clock,
 * so skew between the host and the API does not move it.
 */
export interface StartIdentity {
  token: string;
  /** When the exchange that minted the token answered. */
  receivedAt: Date;
  /** The token lifetime in seconds from `receivedAt`. */
  expiresIn: number;
  now: () => Date;
}

/**
 * How long before its expiry a token stops being presented. The login refuses
 * a token that no longer verifies (ADR 0058 D2), so one that could expire in
 * flight is withheld, and the account binds at its next sign-in instead.
 */
const IDENTITY_TOKEN_MARGIN_MS = 30_000;

/** The token, if the clock still leaves it the margin; `undefined` otherwise. */
function presentableToken(identity: StartIdentity | null): string | undefined {
  if (identity === null) return undefined;
  const deadline =
    identity.receivedAt.getTime() + identity.expiresIn * 1000 - IDENTITY_TOKEN_MARGIN_MS;
  return identity.now().getTime() < deadline ? identity.token : undefined;
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
  exporter: LoginSecretExporter,
  identity: StartIdentity | null = null,
  signal?: AbortSignal
): Promise<void> {
  // Read before the export, so a session that cannot name its account never
  // mints a secret buffer.
  const accountId = exporter.accountId();
  const secret = await exportLoginSecret(exporter);
  try {
    signal?.throwIfAborted();
    // The clock is read after the export, the last await before the start.
    await facade.start(secret, accountId, presentableToken(identity));
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
