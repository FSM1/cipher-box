/**
 * The identity exchange (ADR 0008 D1/D2). CipherBox verifies the provider
 * credential and mints the token the Core Kit logs in with.
 *
 * Spoken over plain HTTP rather than through the engine: this runs before a
 * login secret exists, and the engine refuses every command until `start`.
 */

/** How a person proved who they are. */
export type IdentityMethod = 'google' | 'email' | 'wallet';

const METHODS: readonly IdentityMethod[] = ['google', 'email', 'wallet'];

export function isIdentityMethod(value: unknown): value is IdentityMethod {
  return typeof value === 'string' && METHODS.includes(value as IdentityMethod);
}

/** A CipherBox identity token and the Core Kit identity it is bound to. */
export interface IdentityCredential {
  method: IdentityMethod;
  token: string;
  /** Passed to `loginWithJWT`; with the verifier it selects the derived key. */
  verifierId: string;
  /** For display only — absent for wallet, which carries no address. */
  email: string | null;
}

export interface IdentityExchange {
  fromGoogleToken(idToken: string): Promise<IdentityCredential>;
  sendEmailCode(email: string): Promise<void>;
  fromEmailCode(email: string, code: string): Promise<IdentityCredential>;
  /** The single-use nonce the wallet's EIP-4361 message embeds. */
  walletNonce(): Promise<string>;
  fromWalletSignature(message: string, signature: string): Promise<IdentityCredential>;
}

interface GrantBody {
  token: string;
  verifierId: string;
  email: string | null;
}

/** Talks to the API's identity surface at `apiBaseUrl`. */
export function createIdentityExchange(apiBaseUrl: string): IdentityExchange {
  const base = apiBaseUrl.replace(/\/+$/, '');

  async function post<T>(path: string, body?: unknown): Promise<T> {
    let response: Response;
    try {
      response = await fetch(`${base}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body ?? {}),
      });
    } catch {
      throw new Error('CipherBox could not be reached — check your connection');
    }
    if (!response.ok) throw new Error(await refusalOf(response));
    return (await response.json()) as T;
  }

  const credential = (method: IdentityMethod, grant: GrantBody): IdentityCredential => ({
    method,
    token: grant.token,
    verifierId: grant.verifierId,
    email: grant.email,
  });

  return {
    async fromGoogleToken(idToken) {
      return credential('google', await post<GrantBody>('/auth/identity/google', { idToken }));
    },
    async sendEmailCode(email) {
      await post('/auth/identity/email/send-code', { email });
    },
    async fromEmailCode(email, code) {
      return credential(
        'email',
        await post<GrantBody>('/auth/identity/email/verify-code', { email, code })
      );
    },
    async walletNonce() {
      return (await post<{ nonce: string }>('/auth/siwe/challenge')).nonce;
    },
    async fromWalletSignature(message, signature) {
      return credential(
        'wallet',
        await post<GrantBody>('/auth/identity/wallet', { message, signature })
      );
    },
  };
}

/**
 * The API's own refusal text, which is written for the member. Anything else
 * that answered — a proxy, an error page — is reported as a bare refusal
 * rather than rendered into the UI.
 */
async function refusalOf(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json();
    const message = (body as { message?: unknown }).message;
    if (typeof message === 'string') return message;
    if (Array.isArray(message) && typeof message[0] === 'string') return message[0];
  } catch {
    /* fall through to the status */
  }
  return `sign-in failed (${response.status})`;
}
