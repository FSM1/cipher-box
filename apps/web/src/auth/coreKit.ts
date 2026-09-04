/**
 * Web3Auth Core Kit on the UI thread: it owns its own popup and redirect flows,
 * so it cannot live in the engine worker (blueprint/web-client.md "Login and
 * identity"). The one thing it produces that the vault cares about is the login
 * secret, which the login flow transfers to the engine.
 */

import {
  COREKIT_STATUS,
  factorKeyCurve,
  FactorKeyTypeShareDescription,
  generateFactorKey,
  keyToMnemonic,
  mnemonicToKey,
  TssShareType,
  WEB3AUTH_NETWORK,
  Web3AuthMPCCoreKit,
} from '@web3auth/mpc-core-kit';
import { Point } from '@tkey/common-types';
import { tssLib } from '@toruslabs/tss-dkls-lib';
import BN from 'bn.js';
import {
  accountIdFromTssPoint,
  isIdentityMethod,
  RecoveryRequiredError,
  type CoreKitSession,
  type IdentityCredential,
  type IdentityMethod,
} from '@cipherbox/login';
import { environment, loginEnv } from '../engine/config';
import type { DeviceIdentity, DeviceIdentityStore } from './deviceIdentity';
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
  /**
   * Whether the account carries a factor policy at all, of whatever kind. The
   * account-wide reading, which a per-kind one cannot give: a member who joined
   * by device approval answers `false` to `hasRecoveryPhrase` and `true` here.
   */
  hasFactorPolicy(): boolean;
  /** Turns the factor policy on; the phrase it returns is shown exactly once. */
  enrollRecoveryPhrase(): Promise<RecoveryEnrollment>;
  /**
   * Best-effort removal of this device's factor (`CoreKitSession`), and the
   * erase of this device's identity key.
   */
  forgetDevice(): Promise<void>;
  /**
   * This device's identity key for the subject that signed in, or `null` before
   * a sign-in names one (ADR 0009 D4).
   */
  deviceIdentity(): DeviceIdentity | null;
  /** The identity token this sign-in used, which the device surface presents. */
  identityToken(): string | null;
  /**
   * A fresh factor for a device this session approves, and never this session's
   * own (ADR 0009 D5). The bytes are the caller's to seal and then to erase.
   */
  mintApprovalFactor(): Promise<Uint8Array>;
  /**
   * Adopt the factor an approver sealed back, and keep it as this device's own
   * so the next sign-in here needs neither a phrase nor a second device.
   */
  adoptApprovalFactor(factorKey: Uint8Array): Promise<void>;
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
 * How many factors an account with no policy carries. Past that count one has
 * been enrolled, whatever kind it is.
 */
const UNENROLLED_FACTORS = 2;

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

  /** The identity this sign-in used; kept through a login held at the policy,
   * which is the state a device-approval request is opened from. */
  private signedInSubject: string | null = null;
  private signedInToken: string | null = null;

  constructor(
    private readonly coreKit: Web3AuthMPCCoreKit,
    private readonly store: SealedStore,
    private readonly identities: DeviceIdentityStore,
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
    this.signedInSubject = credential.verifierId;
    this.signedInToken = credential.token;
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

  hasFactorPolicy(): boolean {
    try {
      return (
        Object.keys(this.coreKit.getKeyDetails().shareDescriptions).length > UNENROLLED_FACTORS
      );
    } catch {
      return false;
    }
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
      const factorKey = await this.storedDeviceFactor();
      if (factorKey) await this.coreKit.inputFactorKey(factorKey);
    } catch {
      // No usable factor here is the recovery path, not a failure.
    }
  }

  /** This device's stored factor as a scalar; `null` when it holds none. */
  private async storedDeviceFactor(): Promise<BN | null> {
    const stored = await this.coreKit.getDeviceFactor();
    return stored ? new BN(stored, 'hex') : null;
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

  accountId(): string {
    return accountIdFromTssPoint(this.coreKit.getKeyDetails().tssPubKey);
  }

  /** The account's key, or blank when this device cannot read it. */
  private accountKey(): string {
    try {
      return this.accountId();
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
      this.signedInSubject = null;
      this.signedInToken = null;
      await this.clearStore();
    }
  }

  deviceIdentity(): DeviceIdentity | null {
    const subject = this.subject();
    return subject === null ? null : this.identities.forSubject(subject);
  }

  /**
   * Which member this browser is signed in as. Read back off the SDK's user
   * info when this instance did not itself log in, which is what a session
   * restored across a reload looks like.
   */
  private subject(): string | null {
    if (this.signedInSubject !== null) return this.signedInSubject;
    let claimed: unknown;
    try {
      claimed = (this.coreKit.getUserInfo() as { verifierId?: unknown }).verifierId;
    } catch {
      return null;
    }
    return typeof claimed === 'string' && claimed !== '' ? claimed : null;
  }

  identityToken(): string | null {
    return this.signedInToken;
  }

  async mintApprovalFactor(): Promise<Uint8Array> {
    if (!this.isLoggedIn()) throw new Error('sign in before you approve a device');
    const factor = generateFactorKey();
    await this.coreKit.createFactor({
      shareType: TssShareType.DEVICE,
      factorKey: factor.private,
      shareDescription: FactorKeyTypeShareDescription.DeviceShare,
    });
    // Manual sync: an uncommitted factor would open nothing on the new device.
    await this.coreKit.commitChanges();
    return scalarBytes(factor.private);
  }

  async adoptApprovalFactor(factorKey: Uint8Array): Promise<void> {
    if (!this.needsRecovery()) throw new Error('this device is not waiting on an approval');
    const scalar = new BN(factorKey);
    await this.coreKit.inputFactorKey(scalar);
    if (!this.isLoggedIn()) throw new Error('that approval does not open this account');
    // Replacing, for the same reason a recovery does: a stored factor the
    // account never learned about must not refuse the one that just worked.
    await this.coreKit.setDeviceFactor(scalar, true);
    await this.coreKit.commitChanges();
  }

  async forgetDevice(): Promise<void> {
    await this.dropDeviceFactor();
    // The identity key is this device's durable local state, so a forget takes
    // it too: a key left behind keeps signing as a device the member erased.
    // Unlike the factor drop it needs no network, so its refusal is reported.
    await this.deviceIdentity()?.forget();
  }

  private async dropDeviceFactor(): Promise<void> {
    // Refused rather than risked: the erase beside this call destroys the only
    // copy of this factor, so dropping it from an account that carries no
    // recovery phrase would take the member's last route in with it. A factor
    // left listed opens nothing once the local store is gone.
    if (!this.hasRecoveryPhrase()) return;
    try {
      const factorKey = await this.storedDeviceFactor();
      if (!factorKey) return;
      await this.coreKit.deleteFactor(Point.fromScalar(factorKey, factorKeyCurve), factorKey);
      // Manual sync: an uncommitted removal leaves the factor live.
      await this.coreKit.commitChanges();
    } catch {
      // Offline, or an account this session cannot re-sync. Best-effort by
      // decision (`CoreKitSession.forgetDevice`): the local erase stands.
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

/**
 * A Core Kit factor key as the 32 big-endian bytes the seal takes. The explicit
 * width is the load-bearing part: `toArray('be')` alone drops leading zeros, so
 * one factor in 256 would travel short and open under a different scalar.
 */
function scalarBytes(scalar: BN): Uint8Array {
  return Uint8Array.from(scalar.toArray('be', 32));
}

/** Builds this tab's Core Kit session from the build-time environment. */
export function createCoreKitSession(
  env: Partial<ImportMetaEnv>,
  store: SealedStore,
  identities: DeviceIdentityStore
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
  return new Web3AuthSession(coreKit, store, identities, verifier);
}
