/**
 * Web3Auth Core Kit on the UI thread: it owns its own popup and redirect flows,
 * so it cannot live in the engine worker (blueprint/web-client.md "Login and
 * identity"). The one thing it produces that the vault cares about is the login
 * secret, which `engine/loginHandoff` transfers to the engine.
 */

import { COREKIT_STATUS, WEB3AUTH_NETWORK, Web3AuthMPCCoreKit } from '@web3auth/mpc-core-kit';
import { tssLib } from '@toruslabs/tss-dkls-lib';
import { environment } from '../engine/config';
import type { LoginSecretExporter } from '../engine/loginHandoff';

/** How a session was established; also the `authStore` login method. */
export type CoreKitLoginMethod = 'google' | 'email';

/**
 * The Core Kit surface the login flow drives. Narrow by construction: the hook
 * never sees a Web3Auth parameter shape, and a test substitutes a plain object.
 */
export interface CoreKitSession extends LoginSecretExporter {
  /** Restores a prior session, if the SDK has one on this device. */
  restore(): Promise<void>;
  /** True once a login (or a restore) has completed on this device. */
  isLoggedIn(): boolean;
  login(method: CoreKitLoginMethod, email?: string): Promise<void>;
  /** How the live session was established, as Core Kit reports it. */
  method(): CoreKitLoginMethod;
  /** The signed-in user's email, when the method carries one. */
  email(): string | null;
  logout(): Promise<void>;
}

/** Adapts the Web3Auth SDK to the narrow session seam above. */
class Web3AuthSession implements CoreKitSession {
  constructor(
    private readonly coreKit: Web3AuthMPCCoreKit,
    private readonly verifier: string,
    private readonly clientId: string
  ) {}

  async restore(): Promise<void> {
    await this.coreKit.init();
  }

  isLoggedIn(): boolean {
    return this.coreKit.status === COREKIT_STATUS.LOGGED_IN;
  }

  async login(method: CoreKitLoginMethod, email?: string): Promise<void> {
    await this.coreKit.loginWithOAuth({
      subVerifierDetails: {
        typeOfLogin: method === 'google' ? 'google' : 'email_passwordless',
        verifier: this.verifier,
        clientId: this.clientId,
        ...(email ? { jwtParams: { login_hint: email } } : {}),
      },
    });
    if (this.coreKit.status !== COREKIT_STATUS.LOGGED_IN) {
      // REQUIRED_SHARE: MFA is on and this device holds no factor. Recovery and
      // device approval are not built yet, so fail rather than half-log-in.
      throw new Error('this device needs approval or a recovery phrase before it can sign in');
    }
    await this.coreKit.commitChanges();
  }

  method(): CoreKitLoginMethod {
    return this.coreKit.getUserInfo().typeOfLogin === 'google' ? 'google' : 'email';
  }

  email(): string | null {
    return this.coreKit.getUserInfo().email ?? null;
  }

  async logout(): Promise<void> {
    if (this.isLoggedIn()) await this.coreKit.logout();
  }

  _UNSAFE_exportTssKey(): Promise<string> {
    return this.coreKit._UNSAFE_exportTssKey();
  }
}

/** Builds this tab's Core Kit session from the build-time environment. */
export function createCoreKitSession(env: Partial<ImportMetaEnv>): CoreKitSession {
  const clientId = env.VITE_WEB3AUTH_CLIENT_ID;
  const verifier = env.VITE_WEB3AUTH_VERIFIER;
  if (!clientId || !verifier) {
    throw new Error('VITE_WEB3AUTH_CLIENT_ID and VITE_WEB3AUTH_VERIFIER must both be configured');
  }

  const coreKit = new Web3AuthMPCCoreKit({
    web3AuthClientId: clientId,
    web3AuthNetwork:
      environment(env) === 'production' ? WEB3AUTH_NETWORK.MAINNET : WEB3AUTH_NETWORK.DEVNET,
    // Core Kit persists its own device-factor share and session id here. The
    // login secret is not among them — it only ever leaves this realm as the
    // transferred buffer — but this store is a bearer path back to a logged-in
    // Core Kit, so its scope is a decision, not a default: see #913.
    storage: window.localStorage,
    manualSync: true,
    tssLib,
  });
  return new Web3AuthSession(coreKit, verifier, clientId);
}
