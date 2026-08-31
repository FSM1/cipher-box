/**
 * The shell's Web3Auth Core Kit session. The host builds the instance; the
 * sequencing that drives it is `@cipherbox/login`'s.
 */

import { invoke } from '@tauri-apps/api/core';
import { tssLib } from '@toruslabs/tss-dkls-lib';
import {
  COREKIT_STATUS,
  FactorKeyTypeShareDescription,
  generateFactorKey,
  mnemonicToKey,
  TssShareType,
  WEB3AUTH_NETWORK,
  Web3AuthMPCCoreKit,
} from '@web3auth/mpc-core-kit';
import BN from 'bn.js';
import {
  accountIdFromTssPoint,
  isIdentityMethod,
  RecoveryRequiredError,
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

/** The Core Kit surface the shell drives beyond the shared login flow. */
export interface ShellCoreKitSession extends CoreKitSession {
  /**
   * Redeems a recovery phrase and mints this device a factor of its own, so the
   * next sign-in on it is ordinary. A phrase that does not open the account
   * leaves the held login as it was, ready for another attempt.
   */
  recoverWithPhrase(phrase: string): Promise<void>;
  /** A login reached the factor policy and this device holds no factor. */
  awaitsRecovery(): boolean;
}

/**
 * What a redemption that did not open the account says. It names both causes
 * the SDK collapses into one refusal: an account this phrase does not open, and
 * an account this device could not reach. A verdict that named only the phrase
 * would tell a member offline that their last route in is gone, and a phrase a
 * member then destroys cannot be re-issued.
 */
const REDEMPTION_FAILED =
  'that recovery phrase did not open this account — check the phrase, and check you are online';

/** The one reading of a typed phrase, so a field and the redemption agree. */
function normalizeRecoveryPhrase(typed: string): string {
  return typed.trim().toLowerCase().replace(/\s+/g, ' ');
}

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
class ShellSession implements ShellCoreKitSession {
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
    this.signedInEmail = credential.email;
    if (!this.isLoggedIn()) await this.useStoredDeviceFactor();
    if (this.isLoggedIn()) {
      await this.coreKit.commitChanges();
      return;
    }
    // A phrase answers a factor policy and nothing else, so only that status
    // raises the prompt: any other one would strand the member at a panel whose
    // own guard refuses the phrase they type into it.
    if (!this.awaitsRecovery()) throw new Error(`the sign-in stopped at ${this.coreKit.status}`);
    throw new RecoveryRequiredError();
  }

  async recoverWithPhrase(phrase: string): Promise<void> {
    if (!this.awaitsRecovery()) throw new Error('this device is not waiting on a recovery phrase');
    let factorKey: BN;
    // Neither the decoder's message nor the SDK's may reach the window: both
    // quote what they were handed, which is the phrase.
    try {
      factorKey = new BN(mnemonicToKey(normalizeRecoveryPhrase(phrase)), 'hex');
    } catch {
      throw new Error('that is not a valid recovery phrase');
    }
    try {
      await this.coreKit.inputFactorKey(factorKey);
    } catch {
      throw new Error(REDEMPTION_FAILED);
    }
    if (!this.isLoggedIn()) throw new Error(REDEMPTION_FAILED);
    try {
      await this.mintDeviceFactor();
      await this.coreKit.commitChanges();
    } catch {
      // The account is open from here, so a device factor is a convenience and
      // never a reason to fail: raising would leave a live session this device's
      // own guard refuses to retry, and the next sign-in simply asks again.
    }
  }

  /**
   * The SDK's own reconstruct tries the hashed share first, which enabling the
   * factor policy deleted, so it stops short even on a device that does hold a
   * factor. Reading that factor back is what keeps a re-login from looking like
   * a lockout.
   */
  private async useStoredDeviceFactor(): Promise<void> {
    try {
      const stored = await this.coreKit.getDeviceFactor();
      if (stored) await this.coreKit.inputFactorKey(new BN(stored, 'hex'));
    } catch {
      // No usable factor here is the recovery path, not a failure.
    }
  }

  /** This device's own factor, so the next sign-in on it needs no phrase. */
  private async mintDeviceFactor(): Promise<void> {
    const factor = generateFactorKey();
    await this.coreKit.createFactor({
      shareType: TssShareType.DEVICE,
      factorKey: factor.private,
      shareDescription: FactorKeyTypeShareDescription.DeviceShare,
    });
    // Replacing: a stored factor the account never learned about — one whose
    // commit failed — would otherwise refuse every later mint and leave this
    // device unable to finish a recovery at all.
    await this.coreKit.setDeviceFactor(factor.private, true);
  }

  awaitsRecovery(): boolean {
    return this.coreKit.status === COREKIT_STATUS.REQUIRED_SHARE;
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
      // A session held short of reconstruction is still a live credential.
      if (this.isLoggedIn() || this.awaitsRecovery()) await this.coreKit.logout();
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
export function createCoreKitSession(config: DesktopConfig): ShellCoreKitSession {
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
