/**
 * The reason codes of the staging soak (blueprint/deploy.md "Scheduled tier"):
 * every soak assertion names one, so the report job and a reader of the job
 * summary tell one failed night from another without the log.
 */

/** A `failure` reason fails the night; a `skip` reason skips one check. */
export type ReasonKind = 'failure' | 'skip';

export const SOAK_REASONS = {
  'unbootstrapped-or-wiped': {
    kind: 'failure',
    meaning: 'the vault has no soak ledger, and the run is not a bootstrap',
  },
  'ledger-unparsable': { kind: 'failure', meaning: 'the soak ledger does not parse' },
  'ledger-unreadable': { kind: 'failure', meaning: 'the soak ledger did not open or save' },
  'listing-unsettled': {
    kind: 'failure',
    meaning: 'the vault listing named a row that did not show in time',
  },
  'bootstrap-failed': {
    kind: 'failure',
    meaning: 'the bootstrap did not archive the soak folder or write a ledger',
  },
  'unrecorded-failure': {
    kind: 'failure',
    meaning: 'a test failed outside every recorded check',
  },
  'test-unfinished': {
    kind: 'failure',
    meaning: 'a test started and never reached its teardown',
  },
  'sign-in-failed': { kind: 'failure', meaning: 'a soak account did not sign in' },
  'marker-unreadable': { kind: 'failure', meaning: 'a ledger marker did not open byte for byte' },
  'name-unread': {
    kind: 'failure',
    meaning: 'the details dialog did not show a marker name in time',
  },
  'sequence-regressed': {
    kind: 'failure',
    meaning: 'a soak name resolved below the ledger sequence',
  },
  'sequence-not-advanced': {
    kind: 'failure',
    meaning: 'the marker of today did not re-resolve at the next sequence',
  },
  'republish-missed': {
    kind: 'failure',
    meaning: 'a name past 60 days was not republished at the next sequence',
  },
  'purge-missed': {
    kind: 'failure',
    meaning: 'a binned marker was purged too early, or was not purged when due',
  },
  'cap-missed': { kind: 'failure', meaning: 'a marker past the cap did not move to the bin' },
  'settings-unread': {
    kind: 'failure',
    meaning: 'the vault settings did not read as a saved record that keeps a bin',
  },
  'routing-unavailable': {
    kind: 'failure',
    meaning: 'the public routing endpoint served no record for a soak name',
  },
  'share-folder-unready': {
    kind: 'failure',
    meaning: 'the owner did not ready a share folder and its marker',
  },
  'link-unminted': { kind: 'failure', meaning: 'the owner did not mint a link or read its epoch' },
  'holder-read-failed': {
    kind: 'failure',
    meaning: 'a link holder did not read a marker byte for byte',
  },
  'claim-unconverted': {
    kind: 'failure',
    meaning: 'a claim did not convert to a granted standing within the invite budget',
  },
  'shared-epoch-stepped': { kind: 'failure', meaning: 'the long-running link epoch moved' },
  'cycle-epoch-flat': {
    kind: 'failure',
    meaning: 'the revoke left a grant, or did not step the read epoch by one',
  },
  'link-not-revoked': { kind: 'failure', meaning: 'a revoked link still opened' },
  'counters-unread': { kind: 'failure', meaning: 'the Grafana query did not answer' },
  'stale-names-grew': { kind: 'failure', meaning: 'stale names grew past the baseline' },
  'walks-skipped-grew': { kind: 'failure', meaning: 'the republisher skipped a walk' },
  'resolve-failures-grew': { kind: 'failure', meaning: 'republisher resolve failures grew' },
  'no-walk-in-window': { kind: 'failure', meaning: 'fewer than two walks in 24 hours' },
  'last-walk-empty': { kind: 'failure', meaning: 'the last republisher walk found no name' },
  'desktop-marker-missing': { kind: 'failure', meaning: 'an OS or browser marker did not open' },
  'browser-marker-unwritten': {
    kind: 'failure',
    meaning: 'the browser marker did not publish with its ledger line',
  },
  'post-deploy-window': {
    kind: 'skip',
    meaning: 'the API started too recently for the republisher walks this counter needs',
  },
} as const satisfies Record<string, { kind: ReasonKind; meaning: string }>;

export type SoakReason = keyof typeof SOAK_REASONS;

export type FailureReason = {
  [R in SoakReason]: (typeof SOAK_REASONS)[R]['kind'] extends 'failure' ? R : never;
}[SoakReason];

export type SkipReason = Exclude<SoakReason, FailureReason>;

export function isSoakReason(value: unknown): value is SoakReason {
  return typeof value === 'string' && Object.hasOwn(SOAK_REASONS, value);
}

export function reasonKind(reason: SoakReason): ReasonKind {
  return SOAK_REASONS[reason].kind;
}

/** An assertion failure that carries its reason code into the error message. */
export class SoakFailure extends Error {
  constructor(
    readonly reason: FailureReason,
    readonly detail: string,
    options?: ErrorOptions
  ) {
    super(`[${reason}] ${detail}`, options);
    this.name = 'SoakFailure';
  }
}
