/**
 * The shell's Web3Auth Core Kit session. The host builds the instance; the
 * sequencing that drives it is `@cipherbox/login`'s.
 */

import { invoke } from '@tauri-apps/api/core';
import { tssLib } from '@toruslabs/tss-dkls-lib';
import { COREKIT_STATUS, WEB3AUTH_NETWORK, Web3AuthMPCCoreKit } from '@web3auth/mpc-core-kit';
import {
  accountIdFromTssPoint,
  isIdentityMethod,
  type CoreKitSession,
  type IdentityCredential,
  type IdentityMethod,
} from '@cipherbox/login';
import type { DesktopConfig } from '../config';

/**
 * Bounds the Web3Auth-held session record and the signatures a login secret
 * re-export needs: long enough to outlast a working session, short enough that
 * the record expires well inside the SDK's 86400s default. The store now
 * survives a quit, so this window is what an unlocked keyring on a shared
 * machine exposes.
 */
const SESSION_SECONDS = 8 * 60 * 60;

/**
 * The Core Kit store, in the OS keyring's custody.
 *
 * What the SDK keeps here is a secp256k1 scalar that both addresses and
 * decrypts the Web3Auth record holding the login secret. The shell seals every
 * slot under a key the keyring holds and this webview never sees
 * (`crates/desktop-seams`, `SealedCoreKitStore`), so a device factor a recovery
 * minted survives a restart without ever sitting on disk in the clear.
 */
class KeyringStore {
  getItem(key: string): Promise<string | null> {
    return invoke<string | null>('core_kit_get_item', { key });
  }

  setItem(key: string, value: string): Promise<void> {
    return invoke('core_kit_set_item', { key, value });
  }

  /** Drops every slot and the key that opens them. */
  purge(): Promise<void> {
    return invoke('core_kit_purge');
  }
}

/** Adapts the Web3Auth SDK to the narrow session seam the login flow drives. */
class ShellSession implements CoreKitSession {
  /** The address the exchange reported; the token deliberately carries no PII. */
  private signedInEmail: string | null = null;

  constructor(
    private readonly coreKit: Web3AuthMPCCoreKit,
    private readonly store: KeyringStore,
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
      // A store that refused the drop is carried alongside the reason the login
      // failed: what the partial sign-in left behind is a device factor, and a
      // caller told only to find a phrase would never learn it is still here.
      const left = await this.store.purge().then(
        () => null,
        (error: unknown) => (error instanceof Error ? error.message : String(error))
      );
      throw new Error(
        left === null
          ? 'this device needs a recovery phrase before it can sign in'
          : `this device needs a recovery phrase before it can sign in, and what that attempt left behind is still on this device: ${left}`
      );
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
      // store standing, a device factor share among it. A refusal here reaches
      // the window: the login flow has already reported the host signed out, so
      // a device that still holds a factor would otherwise say nothing.
      await this.store.purge();
    }
  }

  _UNSAFE_exportTssKey(): Promise<string> {
    return this.coreKit._UNSAFE_exportTssKey();
  }

  accountId(): string {
    return accountIdFromTssPoint(this.coreKit.getKeyDetails().tssPubKey);
  }
}

/** Builds the shell's Core Kit session from the build-time environment. */
export function createCoreKitSession(config: DesktopConfig): CoreKitSession {
  const store = new KeyringStore();
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
