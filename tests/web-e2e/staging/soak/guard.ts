/**
 * The input check of the soak workflow, and the nightly pick of its suite tag.
 * The suite runs with the soak secrets, so its source must be a commit on main:
 * a staging tag resolved to its commit, or a commit SHA. Every later job checks
 * out that SHA, never a name, so a branch or a moved tag cannot change what
 * runs.
 */

/** The tag shape `tag-staging.yml` mints: `staging-<YYYYMMDD>-release-<n>`. */
const RELEASE_TAG = /^staging-(\d{8})-release-(\d+)$/;

const SHA = /^[0-9a-f]{40}$/;

/** The newest release tag in `names`, by date and then by release number; `null` for none. */
export function newestStagingTag(names: readonly string[]): string | null {
  let best: { name: string; date: string; release: number } | null = null;
  for (const raw of names) {
    const name = raw.trim();
    const match = RELEASE_TAG.exec(name);
    if (match === null) continue;
    const candidate = { name, date: match[1]!, release: Number(match[2]) };
    if (
      best === null ||
      candidate.date > best.date ||
      (candidate.date === best.date && candidate.release > best.release)
    ) {
      best = candidate;
    }
  }
  return best?.name ?? null;
}

export type RefShape = 'tag' | 'sha' | 'refused';

/** What the check must resolve for `ref` before it can decide. */
export function refShape(ref: string): RefShape {
  if (RELEASE_TAG.test(ref)) return 'tag';
  if (SHA.test(ref)) return 'sha';
  return 'refused';
}

export interface GuardInputs {
  /** The `ref` input, or the run's own SHA when the input is empty. */
  readonly ref: string;
  /** The `base-url` input; empty takes the expected URL. */
  readonly baseUrl: string;
  /** The `STAGING_APP_URL` variable. */
  readonly expectedUrl: string;
  /** The commit a tag `ref` points at; `null` when no such tag exists. Unused for a SHA. */
  readonly tagCommit: string | null;
  /** The status of the compare from main to the resolved commit. */
  readonly compareStatus: string;
}

export type GuardDecision =
  | {
      readonly kind: 'accept';
      readonly sha: string;
      readonly baseUrl: string;
      /** The ref as given, for the summary only. */
      readonly label: string;
    }
  | { readonly kind: 'refuse'; readonly reason: string };

/** The decision. No refusal repeats an input, because an input can carry a workflow command. */
export function decideGuard(inputs: GuardInputs): GuardDecision {
  const refuse = (reason: string): GuardDecision => ({ kind: 'refuse', reason });
  if (inputs.expectedUrl.trim() === '') {
    return refuse('the staging environment has no STAGING_APP_URL variable');
  }
  const baseUrl = inputs.baseUrl.trim() === '' ? inputs.expectedUrl : inputs.baseUrl;
  if (baseUrl !== inputs.expectedUrl) {
    return refuse('base-url must be the staging app URL, the STAGING_APP_URL variable');
  }

  let sha: string;
  switch (refShape(inputs.ref)) {
    case 'tag':
      if (inputs.tagCommit === null) return refuse('ref names no staging release tag');
      if (!SHA.test(inputs.tagCommit)) return refuse('the tag does not resolve to a commit');
      sha = inputs.tagCommit;
      break;
    case 'sha':
      sha = inputs.ref;
      break;
    case 'refused':
      return refuse(
        'ref must be a staging-<date>-release-<n> tag or a full commit SHA on main. A branch or a refs/pull/* ref is refused.'
      );
  }

  // Base-to-head: an ancestor of main compares as `behind`, main's own HEAD as
  // `identical`; anything off main is `ahead` or `diverged`.
  if (inputs.compareStatus !== 'identical' && inputs.compareStatus !== 'behind') {
    return refuse('the suite commit is not on main');
  }
  return { kind: 'accept', sha, baseUrl, label: inputs.ref };
}
