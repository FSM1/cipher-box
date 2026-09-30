/**
 * The input check of the soak workflow, and the nightly pick of its suite tag.
 * The suite runs with the soak secrets, so its source must be a commit on main:
 * a staging tag resolved to its commit, or a commit SHA. Every later job checks
 * out that SHA, never a name, so a branch or a moved tag cannot change what
 * runs.
 */

// No `m` flag: `$` then matches only at the end of the input, and a JS `$`
// does not match before a trailing newline, so no second output line passes.
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

/** What a ref resolves to. */
export type ResolvedRef =
  | { readonly kind: 'no-tag' }
  | { readonly kind: 'not-a-commit' }
  | { readonly kind: 'commit'; readonly sha: string };

/** The compare statuses GitHub documents, and `missing` for every other answer. */
export type CompareStatus = 'identical' | 'behind' | 'ahead' | 'diverged' | 'missing';

export interface GuardInputs {
  /** The `ref` input, or the run's own SHA when the input is empty. */
  readonly ref: string;
  /** The `base-url` input; empty takes the expected URL. */
  readonly baseUrl: string;
  /** The `STAGING_APP_URL` variable. */
  readonly expectedUrl: string;
  /** What `ref` resolves to: a tag through the API, a SHA as itself. */
  readonly commit: ResolvedRef;
  /** The status of the compare from the main commit to the resolved commit. */
  readonly compareStatus: CompareStatus;
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
  if (refShape(inputs.ref) === 'refused') {
    return refuse(
      'ref must be a staging-<date>-release-<n> tag or a full commit SHA on main. A branch or a refs/pull/* ref is refused.'
    );
  }
  if (inputs.commit.kind === 'no-tag') return refuse('ref names no staging release tag');
  if (inputs.commit.kind === 'not-a-commit') return refuse('the tag does not point at a commit');
  if (!SHA.test(inputs.commit.sha)) return refuse('the ref resolved to no commit SHA');

  // Base-to-head: an ancestor of main compares as `behind`, main's own HEAD as
  // `identical`; anything off main is `ahead` or `diverged`.
  if (inputs.compareStatus !== 'identical' && inputs.compareStatus !== 'behind') {
    return refuse('the suite commit is not on main');
  }
  return { kind: 'accept', sha: inputs.commit.sha, baseUrl, label: inputs.ref };
}

/** The part of `fetch` the reads use, so a test can answer them. */
export type Fetch = (
  url: string,
  init: { headers: Record<string, string> }
) => Promise<{ status: number; json(): Promise<unknown> }>;

export interface GitHubApi {
  readonly api: string;
  readonly repo: string;
  readonly token: string;
  readonly fetch: Fetch;
}

async function read(gh: GitHubApi, path: string): Promise<unknown> {
  const response = await gh.fetch(`${gh.api}/repos/${gh.repo}/${path}`, {
    headers: { authorization: `Bearer ${gh.token}`, accept: 'application/vnd.github+json' },
  });
  if (response.status === 404) return null;
  if (response.status !== 200) {
    throw new Error(`the GitHub API answered ${response.status} for a guard read`);
  }
  return response.json();
}

interface GitObject {
  object?: { type?: unknown; sha?: unknown };
}

/** Annotated tags that point at annotated tags, followed at most this many times. */
const TAG_HOPS = 4;

/** The commit a tag points at, through annotated tag objects. */
export async function tagCommit(gh: GitHubApi, tag: string): Promise<ResolvedRef> {
  let answer = await read(gh, `git/ref/tags/${tag}`);
  if (answer === null) return { kind: 'no-tag' };
  for (let hop = 0; hop <= TAG_HOPS; hop += 1) {
    const object = (answer as GitObject | null)?.object;
    if (typeof object?.sha !== 'string') return { kind: 'not-a-commit' };
    if (object.type === 'commit') return { kind: 'commit', sha: object.sha };
    if (object.type !== 'tag' || hop === TAG_HOPS) return { kind: 'not-a-commit' };
    answer = await read(gh, `git/tags/${object.sha}`);
  }
  return { kind: 'not-a-commit' };
}

/** The commit of the `main` branch, by its full ref, so a tag named `main` cannot stand in. */
export async function mainCommit(gh: GitHubApi): Promise<string> {
  const object = ((await read(gh, 'git/ref/heads/main')) as GitObject | null)?.object;
  if (object?.type !== 'commit' || typeof object.sha !== 'string' || !SHA.test(object.sha)) {
    throw new Error('refs/heads/main does not resolve to a commit');
  }
  return object.sha;
}

const COMPARE_STATUSES: ReadonlySet<string> = new Set(['identical', 'behind', 'ahead', 'diverged']);

export async function compareStatus(
  gh: GitHubApi,
  base: string,
  head: string
): Promise<CompareStatus> {
  const status = ((await read(gh, `compare/${base}...${head}`)) as { status?: unknown } | null)
    ?.status;
  return typeof status === 'string' && COMPARE_STATUSES.has(status)
    ? (status as CompareStatus)
    : 'missing';
}
