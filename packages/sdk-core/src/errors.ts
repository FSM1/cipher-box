/**
 * SDK-core error classes.
 *
 * Lives in sdk-core (not sdk) so folder/index.ts and file/index.ts can throw
 * these without creating a circular dependency.
 */

export class ConflictError extends Error {
  readonly ipnsName: string;
  readonly attempts: number;
  readonly lastRemoteSeq: bigint;

  constructor(ipnsName: string, attempts: number, lastRemoteSeq: bigint) {
    super(
      `IPNS conflict unresolved after ${attempts} attempts for ${ipnsName} (remote seq: ${lastRemoteSeq})`
    );
    this.name = 'ConflictError';
    this.ipnsName = ipnsName;
    this.attempts = attempts;
    this.lastRemoteSeq = lastRemoteSeq;
  }
}

export function isConflictExhausted(error: unknown): error is ConflictError {
  return error instanceof ConflictError;
}
