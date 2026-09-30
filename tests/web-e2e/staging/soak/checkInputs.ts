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
import {
  compareStatus,
  decideGuard,
  mainCommit,
  newestStagingTag,
  refShape,
  tagCommit,
  type GitHubApi,
  type ResolvedRef,
} from './guard';

function env(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim() === '') throw new Error(`${name} is not set`);
  return value;
}

async function guard(): Promise<number> {
  const gh: GitHubApi = {
    api: process.env.GITHUB_API_URL ?? 'https://api.github.com',
    repo: env('GITHUB_REPOSITORY'),
    token: env('GH_TOKEN'),
    fetch,
  };
  const ref = env('SOAK_REF');
  const shape = refShape(ref);
  const commit: ResolvedRef =
    shape === 'tag'
      ? await tagCommit(gh, ref)
      : shape === 'sha'
        ? { kind: 'commit', sha: ref }
        : { kind: 'no-tag' };
  const decision = decideGuard({
    ref,
    baseUrl: process.env.SOAK_BASE_URL ?? '',
    expectedUrl: process.env.STAGING_APP_URL ?? '',
    commit,
    compareStatus:
      commit.kind === 'commit'
        ? await compareStatus(gh, await mainCommit(gh), commit.sha)
        : 'missing',
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
