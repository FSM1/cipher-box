/**
 * The shell's Web3Auth Core Kit session. The host builds the instance; the
 * sequencing that drives it is `@cipherbox/login`'s.
 */

import { tssLib } from '@toruslabs/tss-dkls-lib';
import { COREKIT_STATUS, WEB3AUTH_NETWORK, Web3AuthMPCCoreKit } from '@web3auth/mpc-core-kit';
import {
  isIdentityMethod,
  type CoreKitSession,
  type IdentityCredential,
  type IdentityMethod,
} from '@cipherbox/login';
import type { DesktopConfig } from '../config';

/**
 * Bounds the Web3Auth-held session record and the signatures a login secret
 * re-export needs: long enough to outlast a working session, short enough not
 * to survive a night on a shared machine, which the SDK's 86400s default does.
 */
const SESSION_SECONDS = 8 * 60 * 60;

/**
 * The Core Kit store, in memory for the process lifetime.
 *
 * What the SDK keeps there is a secp256k1 scalar that both addresses and
 * decrypts the Web3Auth record holding the login secret. Nothing on this host
 * may hold that at rest until the shell has its keychain-backed CredentialStore
 * seam (blueprint/desktop.md, "Engine wiring"), so a restart is a fresh sign-in
 * rather than a scalar left on disk.
 */
class MemoryStore {
  private readonly items = new Map<string, string>();

  getItem(key: string): Promise<string | null> {
    return Promise.resolve(this.items.get(key) ?? null);
  }

  setItem(key: string, value: string): Promise<void> {
    this.items.set(key, value);
    return Promise.resolve();
  }

  purge(): void {
    this.items.clear();
  }
}

/** Adapts the Web3Auth SDK to the narrow session seam the login flow drives. */
class ShellSession implements CoreKitSession {
  /** The address the exchange reported; the token deliberately carries no PII. */
  private signedInEmail: string | null = null;

  constructor(
    private readonly coreKit: Web3AuthMPCCoreKit,
    private readonly store: MemoryStore,
    private readonly verifier: string
  ) {}

  async restore(): Promise<void> {
    await this.coreKit.init();
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
      // REQUIRED_SHARE: MFA is on and this device holds no factor. Recovery is
      // not built here yet, so fail rather than half-log-in, and end the
      // partial session rather than leave it resident on the device.
      await this.coreKit.logout().catch(() => undefined);
      this.store.purge();
      throw new Error('this device needs a recovery phrase before it can sign in');
    }
    await this.coreKit.commitChanges();
    this.signedInEmail = credential.email;
  }

  /**
   * Read back off the token's own `method` claim, which the SDK parses into
   * its user info.
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
      // The SDK's own logout blanks its session id and leaves the rest of its
      // store standing, a device factor share among it.
      this.store.purge();
    }
  }

  _UNSAFE_exportTssKey(): Promise<string> {
    return this.coreKit._UNSAFE_exportTssKey();
  }
}

/** Builds the shell's Core Kit session from the build-time environment. */
export function createCoreKitSession(config: DesktopConfig): CoreKitSession {
  const store = new MemoryStore();
  const coreKit = new Web3AuthMPCCoreKit({
    web3AuthClientId: config.web3AuthClientId,
    web3AuthNetwork:
      config.environment === 'production' ? WEB3AUTH_NETWORK.MAINNET : WEB3AUTH_NETWORK.DEVNET,
    storage: store,
    sessionTime: SESSION_SECONDS,
    manualSync: true,
    tssLib,
  });
  return new ShellSession(coreKit, store, config.verifier);
}
