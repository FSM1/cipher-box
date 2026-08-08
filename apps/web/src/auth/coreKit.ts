/**
 * Web3Auth Core Kit on the UI thread: it owns its own popup and redirect flows,
 * so it cannot live in the engine worker (blueprint/web-client.md "Login and
 * identity"). The one thing it produces that the vault cares about is the login
 * secret, which `engine/loginHandoff` transfers to the engine.
 */

import { COREKIT_STATUS, WEB3AUTH_NETWORK, Web3AuthMPCCoreKit } from '@web3auth/mpc-core-kit';
import { tssLib } from '@toruslabs/tss-dkls-lib';
import { environment, loginEnv } from '../engine/config';
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
    private readonly store: Storage,
    private readonly verifier: string,
    private readonly clientId: string
  ) {}

  async restore(): Promise<void> {
    try {
      await this.coreKit.init();
    } catch (failure) {
      // Only an unreadable store wedges the next login through that same read.
      // A restore that failed for any other reason — the SDK's feature check
      // has no network — must leave a good store standing.
      if (!this.storeIsReadable()) this.clearStore();
      throw failure;
    }
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
      // device approval are not built yet, so fail rather than half-log-in, and
      // end the partial session rather than leave it resident on the device.
      await this.coreKit.logout().catch(() => undefined);
      this.clearStore();
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
    try {
      if (this.isLoggedIn()) await this.coreKit.logout();
    } finally {
      this.clearStore();
    }
  }

  /**
   * The SDK's own logout blanks its session id in place and leaves the rest of
   * its store standing — a device factor share among it, once MFA is reachable.
   * So every path that leaves this device without a usable session clears it
   * here, whether the session ended, was refused, or was never readable.
   */
  private clearStore(): void {
    this.store.removeItem(this.coreKit._storageKey);
  }

  /** The SDK reads its store as `JSON.parse(raw || '{}')[key]`; nothing else opens. */
  private storeIsReadable(): boolean {
    const raw = this.store.getItem(this.coreKit._storageKey);
    if (!raw) return true;
    try {
      const parsed: unknown = JSON.parse(raw);
      return typeof parsed === 'object' && parsed !== null;
    } catch {
      return false;
    }
  }

  _UNSAFE_exportTssKey(): Promise<string> {
    return this.coreKit._UNSAFE_exportTssKey();
  }
}

/**
 * Bounds two things at once, which is what sets the value: the Web3Auth-held
 * session record the stored id redeems, and `session_token_exp_second` on the
 * signatures a login secret re-export needs. So it has to outlast a working
 * session — a tab past it cannot be promoted to leader — while still not
 * surviving a night on a shared machine, which the SDK's 86400s default does.
 */
const SESSION_SECONDS = 8 * 60 * 60;

/** Builds this tab's Core Kit session from the build-time environment. */
export function createCoreKitSession(env: Partial<ImportMetaEnv>): CoreKitSession {
  const { clientId, verifier } = loginEnv(env);
  // Origin-wide by decision, not by default: a tab promoted to leader re-exports
  // the login secret from its own restored Core Kit session
  // (`EngineClient.promote`), so a per-tab store would strand every tab that did
  // not itself log in. What sits in it is a secp256k1 scalar that both addresses
  // and decrypts a Web3Auth-held record holding the shares an export needs, so
  // it is bearer key material and `SESSION_SECONDS` is its only other bound.
  const store = window.localStorage;

  const coreKit = new Web3AuthMPCCoreKit({
    web3AuthClientId: clientId,
    web3AuthNetwork:
      environment(env) === 'production' ? WEB3AUTH_NETWORK.MAINNET : WEB3AUTH_NETWORK.DEVNET,
    storage: store,
    sessionTime: SESSION_SECONDS,
    manualSync: true,
    tssLib,
  });
  return new Web3AuthSession(coreKit, store, verifier, clientId);
}
