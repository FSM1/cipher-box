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
  RecoveryRequiredError,
  type CoreKitSession,
  type IdentityCredential,
  type IdentityMethod,
} from '@cipherbox/login';
import { environment, loginEnv } from '../engine/config';
import { indexedDbWrappingKeys, SealedStore } from './sealedStore';

/** The Core Kit surface the web host drives beyond the shared login flow. */
export interface WebCoreKitSession extends CoreKitSession {
  /**
   * Redeems a recovery phrase and mints this device a factor of its own, so the
   * next sign-in on it is ordinary. A phrase that does not open the account
   * leaves the session and the store as they were, ready for another attempt.
   */
  recoverWithPhrase(phrase: string): Promise<void>;
  /** Whether this account already carries a recovery phrase. */
  hasRecoveryPhrase(): boolean;
  /** Turns the factor policy on; the phrase it returns is shown exactly once. */
  enrollRecoveryPhrase(): Promise<RecoveryEnrollment>;
}

/**
 * What an enrollment produced. The phrase is returned even when a later step
 * could not be confirmed: once `enableMFA` has cut the policy, those words are
 * the member's only way onto a new device, and losing them to a failed sync is
 * a permanent lockout — a warning beside them is not.
 */
export interface RecoveryEnrollment {
  /** The 24 words, to be shown exactly once. */
  phrase: string;
  /** What could not be confirmed after the policy was cut; `null` when all did. */
  warning: string | null;
}

/** What the Core Kit's own serializer emits, and so what a field must collect. */
export const RECOVERY_PHRASE_WORDS = 24;

/**
 * Whether one of the SDK's flattened factor descriptions is the recovery
 * factor. The share index carries it as well as the label, because the SDK
 * stamps an index on every factor it writes but defaults an unnamed factor's
 * label to `Other` — v1 read the label alone and told accounts that held a
 * phrase they had none.
 */
function isRecoveryFactor(entry: string): boolean {
  let described: { module?: unknown; tssShareIndex?: unknown };
  try {
    described = JSON.parse(entry) as typeof described;
  } catch {
    return false;
  }
  return (
    described.module === FactorKeyTypeShareDescription.SeedPhrase ||
    described.tssShareIndex === TssShareType.RECOVERY
  );
}

/** The one reading of a typed phrase, so a field and the redemption agree. */
export function normalizeRecoveryPhrase(typed: string): string {
  return typed.trim().toLowerCase().replace(/\s+/g, ' ');
}

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
    if (!this.isLoggedIn()) await this.useStoredDeviceFactor();
    if (this.isLoggedIn()) {
      await this.coreKit.commitChanges();
      return;
    }
    // A phrase answers a factor policy and nothing else, so only that status
    // raises the prompt: any other one would strand the member at a panel whose
    // own guard refuses the phrase they type into it.
    if (!this.needsRecovery()) throw new Error(`the sign-in stopped at ${this.coreKit.status}`);
    throw new RecoveryRequiredError();
  }

  hasRecoveryPhrase(): boolean {
    let described: string[][];
    try {
      described = Object.values(this.coreKit.getKeyDetails().shareDescriptions);
    } catch {
      return false;
    }
    // By what each factor says it is, not by factor count: a device-approval
    // factor would take the count past its unenrolled two and report a phrase
    // nobody was ever shown.
    return described.some((entries) => entries.some(isRecoveryFactor));
  }

  async recoverWithPhrase(phrase: string): Promise<void> {
    if (!this.needsRecovery()) throw new Error('this device is not waiting on a recovery phrase');
    let factorKey: BN;
    // Neither the decoder's message nor the SDK's may reach the UI: both quote
    // what they were handed, which is the phrase.
    try {
      factorKey = new BN(mnemonicToKey(normalizeRecoveryPhrase(phrase)), 'hex');
    } catch {
      throw new Error('that is not a valid recovery phrase');
    }
    try {
      await this.coreKit.inputFactorKey(factorKey);
      if (!this.isLoggedIn()) throw new Error('reconstruction stopped short');
    } catch {
      throw new Error('that recovery phrase does not open this account');
    }
    // The account is open from here, so a device factor is a convenience and
    // never a reason to fail: raising would leave a live session this device's
    // own guard refuses to retry, and the next sign-in simply asks again.
    try {
      await this.mintDeviceFactor();
      await this.coreKit.commitChanges();
    } catch {
      return;
    }
  }

  async enrollRecoveryPhrase(): Promise<RecoveryEnrollment> {
    if (!this.isLoggedIn()) throw new Error('sign in before setting up a recovery phrase');
    // Manual sync: anything still pending has to land before the policy is cut.
    await this.coreKit.commitChanges();
    const before = this.accountKey();
    const factorKeyHex = await this.coreKit.enableMFA({
      // Unnamed, Web3Auth labels it "Other" and no later read tells it from a
      // device factor.
      shareDescription: FactorKeyTypeShareDescription.SeedPhrase,
    });
    // Read before anything that can fail: past `enableMFA` the hashed cloud
    // share is gone, so these words are the account's only spare key.
    const phrase = keyToMnemonic(factorKeyHex);
    try {
      await this.coreKit.commitChanges();
    } catch {
      return { phrase, warning: 'the enrollment could not be synced — reload and check it landed' };
    }
    // The login secret is this vault's root seed, so an account key that moved
    // under enrollment would leave every published byte unreachable.
    const after = this.accountKey();
    if (before && after && after !== before) {
      return {
        phrase,
        warning: 'the account key changed while enrolling — this vault may be lost',
      };
    }
    return { phrase, warning: null };
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

  /** A login reached the factor policy and this device holds no factor. */
  private needsRecovery(): boolean {
    return this.coreKit.status === COREKIT_STATUS.REQUIRED_SHARE;
  }

  /**
   * The account's public identifier, as the two coordinates of its TSS public
   * key. Refuses rather than answering blank: a nameless account would share
   * the default store namespace with every other one on this profile, and the
   * epoch floor that lands there locks the lower-epoch account out for good.
   */
  accountId(): string {
    const key = this.accountKey();
    if (!key) throw new Error('the account key could not be read on this device');
    return key;
  }

  /** The account's TSS public key; blank when this device cannot read it. */
  private accountKey(): string {
    try {
      const point = this.coreKit.getKeyDetails().tssPubKey;
      if (!point?.x || !point.y) return '';
      // Separated, not concatenated: hex drops leading zeroes, so two different
      // points could otherwise spell one name.
      return `${point.x.toString('hex')}-${point.y.toString('hex')}`;
    } catch {
      return '';
    }
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
