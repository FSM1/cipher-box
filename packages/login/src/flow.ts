/**
 * The login sequencing, host-agnostic (ADR 0008 D3): provider credential → API
 * exchange → Core Kit login → secret export → `start(secret)`. Credential
 * collection is injected, and so is the facade this starts, because both differ
 * per host; everything between them is this file and is shared.
 */

import { collectedMethods, type CollectedMaterial, type CredentialCollector } from './collector';
import type { IdentityCredential, IdentityExchange, IdentityMethod } from './identity';
import { handOffLoginSecret, type LoginFacade } from './secret';
import {
  RecoveryRequiredError,
  type AccountRecord,
  type CoreKitSession,
  type LoginProgress,
  type SecretRearm,
} from './session';

/** What the sequencing needs from the host it runs on. */
export interface LoginHost<C extends CollectedMaterial = CollectedMaterial> {
  /** The API's identity surface — one network map for every host. */
  exchange: IdentityExchange;
  collector: CredentialCollector<C>;
  /** This host's Core Kit session; `null` until it is built and its restore settles. */
  session: CoreKitSession | null;
  /** The facade to start; `null` until this host has one. */
  facade: LoginFacade | null;
  secrets: SecretRearm | null;
  account: AccountRecord;
  progress: LoginProgress;
  /** Runs once a logout has torn the facade down, so the host can replace it. */
  afterLogout?: () => void;
  /**
   * Announces the session end to the host's other contexts, before either half
   * tears down. Optional: a host whose session cannot outlive this context has
   * nobody to tell.
   */
  endsSessionElsewhere?: () => void;
}

export interface LoginFlow<C extends CollectedMaterial = CollectedMaterial> {
  /** The methods this host collects for, in the order a front door should show them. */
  readonly methods: readonly IdentityMethod[];
  offers(method: IdentityMethod): boolean;
  loginWithGoogle(collected: C['google']): Promise<void>;
  /** Asks CipherBox to deliver a verification code. */
  sendEmailCode(email: string): Promise<void>;
  loginWithEmailCode(collected: C['email']): Promise<void>;
  /** Issues the single-use nonce the wallet's EIP-4361 message embeds. */
  walletNonce(): Promise<string>;
  loginWithWallet(collected: C['wallet']): Promise<void>;
  /**
   * Finishes a login that stopped at the factor policy, from the phrase alone.
   * Rejects when the phrase does not open the account — leaving that login still
   * held — and when the engine refuses the secret it then exports.
   */
  recoverWithPhrase(phrase: string): Promise<void>;
  logout(): Promise<void>;
  /**
   * Forget this device: everything a logout does, and first the erase a logout
   * deliberately does not do — the engine's durable seams, this device's Core
   * Kit store and wrapping key, and a best-effort drop of its factor.
   *
   * Never reached from a logout, which is the whole point of the affordance
   * (blueprint/web-client.md "Logout"). Offline-capable: the only network leg
   * is the factor drop, whose failure the local erase does not wait on.
   */
  forgetDevice(): Promise<void>;
  /**
   * Hands the engine its secret for a Core Kit session that outlived the page.
   * A no-op unless one is live, and it never rejects: nothing asked for it.
   * Every caller awaits the one attempt, so a host gating a route on "still
   * deciding" learns it has settled whichever consumer asked.
   */
  resume(): Promise<void>;
}

/**
 * There is one engine per host and one cold start per page, so these guards are
 * module-scoped: every consumer drives the same transitions, and a second one
 * must not start a second login. The restore latch keys on the session *and* the
 * facade, because a host replaces either independently: a facade that never
 * received the secret must still get it, however old the session is. It holds
 * the handoff itself, not a flag, so every caller awaits the one attempt and
 * they all learn together when it has settled.
 */
let inFlight = false;
let restore: { session: CoreKitSession; facade: LoginFacade | null; done: Promise<void> } | null =
  null;
/**
 * The provider session a session end retired, or `'any'` where the end could not
 * name one because none was built yet. Cleared by the next deliberate login.
 *
 * A provider session can outlive the end that retired it — it arrived after the
 * end reached this context, or its own teardown refused — and `resume()` would
 * otherwise hand the engine its secret straight back, re-entering the session
 * that just ended and, after a forget, re-seeding what it erased.
 */
let retired: CoreKitSession | 'any' | null = null;

/**
 * Clears the module-scoped latches. For a host's tests, which share one module
 * instance where a document would have reloaded between them; nothing in the app
 * has a second document's worth of state to drop.
 */
export function resetLoginFlowLatches(): void {
  inFlight = false;
  restore = null;
  retired = null;
}

/**
 * Runs `leg` and reports its refusal instead of throwing it, so a caller can
 * finish the legs that do not depend on it.
 */
async function refusalOf(leg: () => Promise<void> | undefined): Promise<unknown> {
  try {
    await leg();
    return undefined;
  } catch (error) {
    return error;
  }
}

export function createLoginFlow<C extends CollectedMaterial = CollectedMaterial>(
  host: LoginHost<C>
): LoginFlow<C> {
  const {
    exchange,
    collector,
    session,
    facade,
    secrets,
    account,
    progress,
    afterLogout,
    endsSessionElsewhere,
  } = host;

  /** Serializes the auth transitions; a collision rejects rather than no-ops. */
  const exclusively = async (step: () => Promise<void>): Promise<void> => {
    if (inFlight) throw new Error('another sign-in is already in progress');
    inFlight = true;
    progress.begin();
    try {
      await step();
    } catch (failure) {
      // A login held at the factor policy is a transition, not a failure: the
      // host renders the phrase prompt, and a banner beside it would be noise.
      if (!(failure instanceof RecoveryRequiredError)) progress.failed(failure);
      throw failure;
    } finally {
      inFlight = false;
      progress.end();
    }
  };

  /**
   * The Core Kit → engine handoff. The secret source is armed first so a
   * leadership failover mid-start can re-export it; every step after that stays
   * inside the failure envelope, so nothing can leave it armed over a host that
   * renders signed out.
   */
  const handOff = async (): Promise<void> => {
    if (!facade || !session) throw new Error('the engine is not ready to accept a login');
    const method = session.method();
    const email = session.email();

    secrets?.use(session);
    try {
      await handOffLoginSecret(facade, session);
      account.signedIn(method, email);
    } catch (failure) {
      secrets?.use(null);
      // A Core Kit session the engine refused is a live credential on this
      // device that nothing in the UI can reach; end it here.
      await session.logout().catch(() => undefined);
      throw failure;
    }
  };

  /**
   * One sequencing for every method: exchange the collected credential, redeem
   * it with the Core Kit, then hand the engine its secret.
   */
  const login = (collect: () => Promise<IdentityCredential>) =>
    exclusively(async () => {
      if (!session) throw new Error('the login provider is not ready');
      retired = null;
      await session.login(await collect());
      await handOff();
    });

  /**
   * Ends the session on this device, `'erase'` also wiping what it leaves
   * behind.
   *
   * Each half erases before its own teardown — the engine's seam wipe rides the
   * transport the facade logout closes, and the factor drop needs the Core Kit
   * session the session logout ends — and tears down even when its erase
   * refused. Every leg runs: a refused engine zeroize must not strand the Core
   * Kit session, and a failed Core Kit logout must not leave the host signed in.
   * The erase refusal is what a half reports: it is the leg the caller asked
   * for, and a teardown that also refused must not stand in front of it.
   */
  const endSession = (mode: 'keep' | 'erase') => {
    const endHalf = async (
      half: {
        forgetDevice?(): Promise<void>;
        logout(): Promise<void>;
      } | null
    ): Promise<void> => {
      const erase = mode === 'erase' ? await refusalOf(() => half?.forgetDevice?.()) : undefined;
      const teardown = await refusalOf(() => half?.logout());
      const refusal = erase ?? teardown;
      if (refusal !== undefined) throw refusal;
    };
    // Outside the serialization gate, which refuses outright while a sign-in is
    // in flight: an end that collided with one would otherwise leave the
    // re-export capability armed and the account still rendered. Announcing here
    // also puts it ahead of the teardown, so the other contexts drop their claim
    // well before this one releases what they would race for.
    retired = session ?? 'any';
    secrets?.use(null);
    restore = null;
    account.signedOut();
    endsSessionElsewhere?.();
    return exclusively(async () => {
      const outcomes = await Promise.allSettled([endHalf(facade), endHalf(session)]);
      // The halves run concurrently, so which one refuses *first* is a race;
      // the engine half is reported by position instead, deterministically.
      const failed = outcomes.find((outcome) => outcome.status === 'rejected');
      if (failed) throw failed.reason as Error;
      // The host owes itself a fresh facade whatever the teardown answered: this
      // one is closed either way, and a host still holding it cannot sign in.
    }).finally(() => afterLogout?.());
  };

  const unavailable = <T>(method: IdentityMethod): Promise<T> =>
    Promise.reject(new Error(`${method} sign-in is not available on this device`));

  const methods = collectedMethods(collector);

  return {
    methods,

    offers: (method) => methods.includes(method),

    loginWithGoogle(collected) {
      const collect = collector.google;
      if (!collect) return unavailable('google');
      return login(async () => exchange.fromGoogleToken(await collect(collected)));
    },

    sendEmailCode(email) {
      if (!collector.email) return unavailable('email');
      return exclusively(() => exchange.sendEmailCode(email));
    },

    loginWithEmailCode(collected) {
      const collect = collector.email;
      if (!collect) return unavailable('email');
      return login(async () => {
        const answer = await collect(collected);
        return exchange.fromEmailCode(answer.email, answer.code);
      });
    },

    walletNonce() {
      if (!collector.wallet) return unavailable<string>('wallet');
      return exchange.walletNonce();
    },

    loginWithWallet(collected) {
      const collect = collector.wallet;
      if (!collect) return unavailable('wallet');
      return login(async () => {
        const proof = await collect(collected);
        return exchange.fromWalletSignature(proof.message, proof.signature);
      });
    },

    recoverWithPhrase(phrase) {
      return exclusively(async () => {
        if (!session?.recoverWithPhrase)
          throw new Error('recovery is not available on this device');
        retired = null;
        await session.recoverWithPhrase(phrase);
        await handOff();
      });
    },

    logout() {
      return endSession('keep');
    },

    forgetDevice() {
      // Fail-closed: a host missing the seam wipe would otherwise get a plain
      // logout under the name of an erase.
      if (!facade?.forgetDevice) {
        return Promise.reject(new Error('this device cannot be forgotten from here'));
      }
      return endSession('erase');
    },

    resume() {
      if (retired === 'any' || retired === session) return Promise.resolve();
      if (!session || !session.isLoggedIn()) return Promise.resolve();
      if (restore !== null && restore.session === session && restore.facade === facade) {
        return restore.done;
      }
      const done = exclusively(handOff).catch(() => undefined);
      restore = { session, facade, done };
      return done;
    },
  };
}
