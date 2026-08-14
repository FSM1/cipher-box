import type { IdentityMethod } from './identity';

/** The address a code was sent to, and the code the member read off it. */
export interface EmailAnswer {
  email: string;
  code: string;
}

/** A signed EIP-4361 statement, as the API verifies it. */
export interface WalletProof {
  message: string;
  /** The `0x`-prefixed EIP-191 hex the wallet returned, sent verbatim. */
  signature: string;
}

/**
 * What each of this host's collectors is handed. A host that already holds the
 * provider's answer when it calls names it here; one that drives its own flow —
 * a native loopback OAuth listener — takes `void` and does the work inside the
 * collector. A method the host cannot collect at all is `never`.
 */
export interface CollectedMaterial {
  google: unknown;
  email: unknown;
  wallet: unknown;
}

/**
 * Credential collection, injected per host (ADR 0008 D3): each collector ends
 * where the provider's own proof does, and the shared sequencing takes over
 * from there.
 *
 * A method absent here is a method this host does not have — desktop reaches no
 * wallet, and a build carrying no Google client ID renders no Google button —
 * so per-method availability is read off this object rather than branched on
 * inside the sequencing.
 */
export interface CredentialCollector<C extends CollectedMaterial = CollectedMaterial> {
  /** Yields a Google ID token for the API to verify. */
  google?(collected: C['google']): Promise<string>;
  email?(collected: C['email']): Promise<EmailAnswer>;
  wallet?(collected: C['wallet']): Promise<WalletProof>;
}

/** The methods this collector offers, in the order a front door should show them. */
export function collectedMethods(collector: CredentialCollector): readonly IdentityMethod[] {
  const offered: IdentityMethod[] = [];
  if (collector.google) offered.push('google');
  if (collector.email) offered.push('email');
  if (collector.wallet) offered.push('wallet');
  return offered;
}
