import type { IdentityCredential, IdentityMethod } from './identity';
import type { LoginSecretExporter } from './secret';

/**
 * A login that reached an account with a factor policy on a device holding no
 * factor. The recovery phrase is the way through it (ADR 0009 D2), so the
 * partial session stays resident until the member redeems a phrase against it
 * or abandons it — ending it here would make every such login a lockout.
 */
export class RecoveryRequiredError extends Error {
  constructor() {
    super('this device needs your recovery phrase before it can sign in');
    this.name = 'RecoveryRequiredError';
  }
}

/**
 * The Core Kit surface the login flow drives. Narrow by construction: the flow
 * never sees a Web3Auth parameter shape, the host builds the instance, and a
 * test substitutes a plain object.
 */
export interface CoreKitSession extends LoginSecretExporter {
  /**
   * Redeems a recovery phrase against a login held at the factor policy. Absent
   * on a host that offers no recovery path; a `RecoveryRequiredError` is then
   * terminal there.
   */
  recoverWithPhrase?(phrase: string): Promise<void>;
  /** Restores a prior session, if the SDK has one on this device. */
  restore(): Promise<void>;
  /** True once a login (or a restore) has completed on this device. */
  isLoggedIn(): boolean;
  /** Redeems a CipherBox identity token for this device's share of the key. */
  login(credential: IdentityCredential): Promise<void>;
  /** How the live session was established; unknown after a bare restore. */
  method(): IdentityMethod | null;
  /** The signed-in user's email, when the method carries one. */
  email(): string | null;
  logout(): Promise<void>;
  /**
   * Drops this device's factor from the account, so what the logout then erases
   * locally cannot be re-derived here. Best-effort by decision: it needs a live
   * session and the network, and a forget must complete offline. A factor left
   * listed is unusable once the local erase lands; the device management that
   * guarantees its removal is not landed. Absent on a host with no factor of
   * its own.
   */
  forgetDevice?(): Promise<void>;
}

/**
 * Where the host records how the session was established and what to display
 * for it — its own UI chrome, never key material, and never *whether* a session
 * exists: that is the started engine's to report.
 */
export interface AccountRecord {
  signedIn(method: IdentityMethod | null, email: string | null): void;
  signedOut(): void;
}

/**
 * The host's re-export capability, armed with the live session for as long as
 * one exists. Web re-exports through it when a tab is promoted to leader.
 */
export interface SecretRearm {
  use(exporter: LoginSecretExporter | null): void;
}

/** How the host renders a transition's progress. */
export interface LoginProgress {
  /** A transition took the flow; nothing has failed yet. */
  begin(): void;
  /** The transition threw `failure`, which the host renders. */
  failed(failure: unknown): void;
  /** The transition settled, whether or not it failed. */
  end(): void;
}
