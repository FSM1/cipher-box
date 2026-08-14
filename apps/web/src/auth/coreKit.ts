/**
 * Web3Auth Core Kit on the UI thread: it owns its own popup and redirect flows,
 * so it cannot live in the engine worker (blueprint/web-client.md "Login and
 * identity"). The one thing it produces that the vault cares about is the login
 * secret, which the login flow transfers to the engine.
 */

import { COREKIT_STATUS, WEB3AUTH_NETWORK, Web3AuthMPCCoreKit } from '@web3auth/mpc-core-kit';
import { tssLib } from '@toruslabs/tss-dkls-lib';
import {
  isIdentityMethod,
  type CoreKitSession,
  type IdentityCredential,
  type IdentityMethod,
} from '@cipherbox/login';
import { environment, loginEnv } from '../engine/config';
import { indexedDbWrappingKeys, SealedStore } from './sealedStore';

/** Adapts the Web3Auth SDK to the narrow session seam the login flow drives. */
class Web3AuthSession implements CoreKitSession {
  /** The address the exchange reported; the token deliberately carries no PII. */
  private signedInEmail: string | null = null;

  constructor(
    private readonly coreKit: Web3AuthMPCCoreKit,
    private readonly store: SealedStore,
    private readonly verifier: string
  ) {}

  async restore(): Promise<void> {
    try {
      await this.coreKit.init();
    } catch (failure) {
      // Only an unreadable store wedges the next login through that same read.
      // A restore that failed for any other reason — the SDK's feature check
      // has no network — must leave a good store standing.
      if (await this.storeIsCorrupt()) await this.clearStore();
      throw failure;
    }
  }

  isLoggedIn(): boolean {
    return this.coreKit.status === COREKIT_STATUS.LOGGED_IN;
  }

  async login(credential: IdentityCredential): Promise<void> {
    await this.coreKit.loginWithJWT({
      verifier: this.verifier,
      verifierId: credential.verifierId,
      idToken: credential.token,
    });
    if (this.coreKit.status !== COREKIT_STATUS.LOGGED_IN) {
      // REQUIRED_SHARE: MFA is on and this device holds no factor. Recovery and
      // device approval are not built yet, so fail rather than half-log-in, and
      // end the partial session rather than leave it resident on the device.
      await this.coreKit.logout().catch(() => undefined);
      await this.clearStore();
      throw new Error('this device needs approval or a recovery phrase before it can sign in');
    }
    await this.coreKit.commitChanges();
    this.signedInEmail = credential.email;
  }

  /**
   * Read back off the token's own `method` claim, which the SDK parses into
   * its user info and keeps across a session restore.
   */
  method(): IdentityMethod | null {
    let claimed: unknown;
    try {
      claimed = (this.coreKit.getUserInfo() as { method?: unknown }).method;
    } catch {
      return null;
    }
    return isIdentityMethod(claimed) ? claimed : null;
  }

  email(): string | null {
    return this.signedInEmail;
  }

  async logout(): Promise<void> {
    try {
      if (this.isLoggedIn()) await this.coreKit.logout();
    } finally {
      this.signedInEmail = null;
      await this.clearStore();
    }
  }

  /**
   * The SDK's own logout blanks its session id in place and leaves the rest of
   * its store standing — a device factor share among it, once MFA is reachable.
   * So every path that leaves this device without a usable session clears it
   * here, whether the session ended, was refused, or was never readable, and
   * takes the wrapping key with it.
   */
  private clearStore(): Promise<void> {
    return this.store.purge(this.coreKit._storageKey);
  }

  /**
   * Whether the store opens but holds something the SDK's own read throws on —
   * it reads as `JSON.parse(raw || '{}')[key]`, and nothing else opens.
   */
  private async storeIsCorrupt(): Promise<boolean> {
    let raw: string | null;
    try {
      raw = await this.store.getItem(this.coreKit._storageKey);
    } catch {
      // A store this device cannot reach is not a corrupt one, and purging it
      // would destroy a session the next attempt could still open.
      return false;
    }
    if (!raw) return false;
    try {
      const parsed: unknown = JSON.parse(raw);
      return typeof parsed !== 'object' || parsed === null;
    } catch {
      return true;
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

/**
 * This origin's Core Kit store: the ciphertext origin-wide in `localStorage`,
 * the key that opens it in IndexedDB.
 *
 * Origin-wide by decision, not by default: a tab promoted to leader re-exports
 * the login secret from its own restored Core Kit session
 * (`EngineClient.promote`), so a per-tab store would strand every tab that did
 * not itself log in.
 */
export function sealedCoreKitStore(): SealedStore {
  return new SealedStore(window.localStorage, indexedDbWrappingKeys(), navigator.locks);
}

/** Builds this tab's Core Kit session from the build-time environment. */
export function createCoreKitSession(
  env: Partial<ImportMetaEnv>,
  store: SealedStore
): CoreKitSession {
  const { web3AuthClientId, verifier } = loginEnv(env);

  const coreKit = new Web3AuthMPCCoreKit({
    web3AuthClientId,
    web3AuthNetwork:
      environment(env) === 'production' ? WEB3AUTH_NETWORK.MAINNET : WEB3AUTH_NETWORK.DEVNET,
    storage: store,
    sessionTime: SESSION_SECONDS,
    manualSync: true,
    tssLib,
  });
  return new Web3AuthSession(coreKit, store, verifier);
}
