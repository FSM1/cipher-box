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

export function createLoginFlow<C extends CollectedMaterial = CollectedMaterial>(
  host: LoginHost<C>
): LoginFlow<C> {
  const { exchange, collector, session, facade, secrets, account, progress, afterLogout } = host;

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
      await session.login(await collect());
      await handOff();
    });

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
        await session.recoverWithPhrase(phrase);
        await handOff();
      });
    },

    logout() {
      return exclusively(async () => {
        // Every leg runs: a refused engine zeroize must not strand the Core Kit
        // session, and a failed Core Kit logout must not leave the host signed in.
        const outcomes = await Promise.allSettled([
          facade?.logout() ?? Promise.resolve(),
          session?.logout() ?? Promise.resolve(),
        ]);
        secrets?.use(null);
        restore = null;
        account.signedOut();
        afterLogout?.();
        const failed = outcomes.find((outcome) => outcome.status === 'rejected');
        if (failed) throw failed.reason as Error;
      });
    },

    resume() {
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
