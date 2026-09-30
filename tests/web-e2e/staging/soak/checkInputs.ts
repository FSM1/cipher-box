/**
 * The workflow entry to `guard.ts`:
 *
 * - `newest-tag <tags-file>` appends `tag=<name>` to `GITHUB_OUTPUT`, from a
 *   file of tag names, one per line, or fails.
 * - `guard` reads `SOAK_REF`, `SOAK_BASE_URL` and `STAGING_APP_URL`, asks the
 *   GitHub API with `GH_TOKEN`, and appends `sha`, `base_url` and `label` to
 *   `GITHUB_OUTPUT`, or fails with the reason.
 */

import { appendFile, readFile } from 'node:fs/promises';
import { decideGuard, newestStagingTag, refShape } from './guard';

function env(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim() === '') throw new Error(`${name} is not set`);
  return value;
}

async function github(path: string): Promise<{ status: number; body: unknown }> {
  const api = process.env.GITHUB_API_URL ?? 'https://api.github.com';
  const response = await fetch(`${api}/repos/${env('GITHUB_REPOSITORY')}/${path}`, {
    headers: {
      authorization: `Bearer ${env('GH_TOKEN')}`,
      accept: 'application/vnd.github+json',
    },
  });
  const body: unknown = response.status === 200 ? await response.json() : null;
  if (response.status !== 200 && response.status !== 404) {
    throw new Error(`the GitHub API answered ${response.status} for a guard read`);
  }
  return { status: response.status, body };
}

interface GitObject {
  object?: { type?: unknown; sha?: unknown };
}

/** The commit a tag points at, through an annotated tag object; `null` for no tag. */
async function tagCommit(tag: string): Promise<string | null> {
  let answer = await github(`git/ref/tags/${tag}`);
  for (let hops = 0; hops < 4; hops += 1) {
    if (answer.status === 404) return null;
    const object = (answer.body as GitObject).object;
    if (typeof object?.sha !== 'string') return null;
    if (object.type === 'commit') return object.sha;
    if (object.type !== 'tag') return null;
    answer = await github(`git/tags/${object.sha}`);
  }
  return null;
}

async function compareStatus(sha: string): Promise<string> {
  const answer = await github(`compare/main...${sha}`);
  const status = (answer.body as { status?: unknown } | null)?.status;
  return typeof status === 'string' ? status : 'missing';
}

async function guard(): Promise<number> {
  const ref = env('SOAK_REF');
  const shape = refShape(ref);
  const commit = shape === 'tag' ? await tagCommit(ref) : shape === 'sha' ? ref : null;
  const decision = decideGuard({
    ref,
    baseUrl: process.env.SOAK_BASE_URL ?? '',
    expectedUrl: process.env.STAGING_APP_URL ?? '',
    tagCommit: shape === 'tag' ? commit : null,
    compareStatus: commit === null ? 'missing' : await compareStatus(commit),
  });
  if (decision.kind === 'refuse') {
    process.stdout.write(`::error::${decision.reason}\n`);
    return 1;
  }
  await appendFile(
    env('GITHUB_OUTPUT'),
    `sha=${decision.sha}\nbase_url=${decision.baseUrl}\nlabel=${decision.label}\n`
  );
  process.stdout.write(`The suite runs from ${decision.label} at ${decision.sha}.\n`);
  return 0;
}

const [command, file] = process.argv.slice(2);

if (command === 'newest-tag' && file !== undefined) {
  const tag = newestStagingTag((await readFile(file, 'utf8')).split('\n'));
  if (tag === null) {
    process.stdout.write(
      '::error::no staging-<date>-release-<n> tag exists, so the soak has no suite source. Tag a staging release first.\n'
    );
    process.exitCode = 1;
  } else {
    await appendFile(env('GITHUB_OUTPUT'), `tag=${tag}\n`);
    process.stdout.write(`The newest staging tag is ${tag}.\n`);
  }
} else if (command === 'guard') {
  process.exitCode = await guard();
} else {
  process.stderr.write('Usage: checkInputs.ts newest-tag <tags-file> | guard\n');
  process.exitCode = 2;
}
