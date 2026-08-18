/**
 * Web3Auth Core Kit on the UI thread: it owns its own popup and redirect flows,
 * so it cannot live in the engine worker (blueprint/web-client.md "Login and
 * identity"). The one thing it produces that the vault cares about is the login
 * secret, which the login flow transfers to the engine.
 */

import {
  COREKIT_STATUS,
  FactorKeyTypeShareDescription,
  generateFactorKey,
  keyToMnemonic,
  mnemonicToKey,
  TssShareType,
  WEB3AUTH_NETWORK,
  Web3AuthMPCCoreKit,
} from '@web3auth/mpc-core-kit';
import { tssLib } from '@toruslabs/tss-dkls-lib';
import BN from 'bn.js';
import {
  isIdentityMethod,
  type CoreKitSession,
  type IdentityCredential,
  type IdentityMethod,
} from '@cipherbox/login';
import { environment, loginEnv } from '../engine/config';
import { indexedDbWrappingKeys, SealedStore } from './sealedStore';

/**
 * A login that reached an account with a factor policy on a device holding no
 * factor. The recovery phrase is the way through it (ADR 0009 D2), so the
 * partial session stays resident until the member either redeems a phrase or
 * abandons it — ending it here would make every such login a lockout.
 */
export class RecoveryRequiredError extends Error {
  constructor() {
    super('this device needs your recovery phrase before it can sign in');
    this.name = 'RecoveryRequiredError';
  }
}

/** The Core Kit surface the web host drives beyond the shared login flow. */
export interface WebCoreKitSession extends CoreKitSession {
  /** Whether a login stopped at a factor policy this device holds no factor for. */
  needsRecovery(): boolean;
  /** Whether this account already carries a factor policy. */
  hasRecoveryPhrase(): boolean;
  /**
   * Redeems a recovery phrase and mints this device a factor of its own, so the
   * next sign-in on it is ordinary. A phrase that does not open the account
   * leaves the session and the store as they were, ready for another attempt.
   */
  recoverWithPhrase(phrase: string): Promise<void>;
  /** Turns the factor policy on; the phrase it returns is shown exactly once. */
  enrollRecoveryPhrase(): Promise<string>;
}

/**
 * Every Core Kit account starts with two factors — the verifier share and the
 * hashed cloud share — so a policy is on only past them.
 */
const UNENROLLED_FACTORS = 2;

/** Adapts the Web3Auth SDK to the narrow session seam the login flow drives. */
class Web3AuthSession implements WebCoreKitSession {
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
    this.signedInEmail = credential.email;
    if (this.coreKit.status !== COREKIT_STATUS.LOGGED_IN) await this.useStoredDeviceFactor();
    if (this.coreKit.status !== COREKIT_STATUS.LOGGED_IN) throw new RecoveryRequiredError();
    await this.coreKit.commitChanges();
  }

  needsRecovery(): boolean {
    return this.coreKit.status === COREKIT_STATUS.REQUIRED_SHARE;
  }

  hasRecoveryPhrase(): boolean {
    try {
      return this.coreKit.getKeyDetails().totalFactors > UNENROLLED_FACTORS;
    } catch {
      return false;
    }
  }

  async recoverWithPhrase(phrase: string): Promise<void> {
    if (!this.needsRecovery()) throw new Error('this device is not waiting on a recovery phrase');
    let factorKey: BN;
    try {
      factorKey = new BN(mnemonicToKey(phrase.trim().toLowerCase().replace(/\s+/g, ' ')), 'hex');
    } catch {
      // Never re-raise the decoder's message: its input is the phrase.
      throw new Error('that is not a valid recovery phrase');
    }
    try {
      await this.coreKit.inputFactorKey(factorKey);
    } catch {
      // Never re-raise the SDK's message either: it quotes what it was handed.
      throw new Error('that recovery phrase does not open this account');
    }
    if (!this.isLoggedIn()) throw new Error('that recovery phrase does not open this account');
    await this.mintDeviceFactor();
    await this.coreKit.commitChanges();
  }

  async enrollRecoveryPhrase(): Promise<string> {
    if (!this.isLoggedIn()) throw new Error('sign in before setting up a recovery phrase');
    // Manual sync: anything still pending has to land before the policy is cut.
    await this.coreKit.commitChanges();
    const before = this.accountKey();
    const factorKeyHex = await this.coreKit.enableMFA({
      // Web3Auth labels an unnamed factor "Other", which no later read can tell
      // apart from a device one.
      shareDescription: FactorKeyTypeShareDescription.SeedPhrase,
    });
    await this.coreKit.commitChanges();
    // The login secret is this vault's root seed, so an account key that moved
    // under enrollment would leave every published byte unreachable. An
    // unreadable key is not evidence that it moved, and withholding the phrase
    // over one would strand a member who now has a policy and nothing to redeem.
    const after = this.accountKey();
    if (before !== null && after !== null && after !== before) {
      throw new Error('the account key changed while enrolling — sign in again before retrying');
    }
    return keyToMnemonic(factorKeyHex);
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
    await this.coreKit.setDeviceFactor(factor.private);
  }

  /** The account's TSS public key, as a value two reads compare on. */
  private accountKey(): string | null {
    const point = this.coreKit.getKeyDetails().tssPubKey;
    if (!point?.x || !point.y) return null;
    return `${point.x.toString('hex')}:${point.y.toString('hex')}`;
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
      // A session held short of reconstruction is still a live credential.
      if (this.isLoggedIn() || this.needsRecovery()) await this.coreKit.logout();
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
): WebCoreKitSession {
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
