import type { IdentityCredential, IdentityMethod } from './identity';
import type { LoginSecretExporter } from './secret';

/**
 * The Core Kit surface the login flow drives. Narrow by construction: the flow
 * never sees a Web3Auth parameter shape, the host builds the instance, and a
 * test substitutes a plain object.
 */
export interface CoreKitSession extends LoginSecretExporter {
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
}

/** Where the host records who is signed in — its own UI chrome, never key material. */
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
