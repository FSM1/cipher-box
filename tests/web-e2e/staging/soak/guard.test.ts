import { describe, expect, it } from 'vitest';
import {
  compareStatus,
  decideGuard,
  mainCommit,
  newestStagingTag,
  refShape,
  tagCommit,
  type Fetch,
  type GitHubApi,
  type GuardInputs,
} from './guard';

const APP = 'https://app.example';
const MAIN_COMMIT = 'a'.repeat(40);
const TAG_OBJECT = 'b'.repeat(40);
const OFF_MAIN = 'c'.repeat(40);

const inputs = (over: Partial<GuardInputs>): GuardInputs => ({
  ref: 'staging-20260928-release-1',
  baseUrl: '',
  expectedUrl: APP,
  commit: { kind: 'commit', sha: MAIN_COMMIT },
  compareStatus: 'behind',
  ...over,
});

/** An API that answers each repository path from `routes`, and 404 for every other path. */
function api(routes: Record<string, { status?: number; body: unknown }>): {
  gh: GitHubApi;
  paths: string[];
} {
  const paths: string[] = [];
  const fetch: Fetch = async (url) => {
    const path = url.replace('https://api.example/repos/o/r/', '');
    paths.push(path);
    const route = routes[path];
    return {
      status: route === undefined ? 404 : (route.status ?? 200),
      json: async () => route?.body,
    };
  };
  return { gh: { api: 'https://api.example', repo: 'o/r', token: 't', fetch }, paths };
}

const ref = (type: string, sha: string) => ({ body: { object: { type, sha } } });

describe('the newest staging tag', () => {
  it('orders by date, then by release number, not by text', () => {
    expect(
      newestStagingTag([
        'staging-20260928-release-9',
        'staging-20260928-release-10',
        'staging-20260927-release-11',
      ])
    ).toBe('staging-20260928-release-10');
  });

  it('skips the v1 tag shapes and blank lines', () => {
    expect(
      newestStagingTag([
        'staging-v0.26.2-rc-1',
        'staging-cipher-box-v0.27.0-rc-1',
        '',
        'staging-20260401-release-1',
      ])
    ).toBe('staging-20260401-release-1');
  });

  it('is null when no release tag exists', () => {
    expect(newestStagingTag(['staging-v0.26.2-rc-1', ''])).toBeNull();
  });
});

describe('the ref shape', () => {
  it('knows a release tag and a full SHA, and refuses every other ref', () => {
    expect(refShape('staging-20260928-release-1')).toBe('tag');
    expect(refShape(MAIN_COMMIT)).toBe('sha');
    for (const refused of [
      'main',
      'refs/pull/12/merge',
      'staging-v0.26.2-rc-1',
      'aaaa',
      'staging-x;y',
      'staging-20260928-release-1\nx',
      'staging-20260928-release-1\nsha=' + MAIN_COMMIT,
      'staging-20260928-release-1/../x',
      MAIN_COMMIT + '\n',
      'x' + MAIN_COMMIT,
    ]) {
      expect(refShape(refused)).toBe('refused');
    }
  });
});

describe('the input check', () => {
  it('accepts a tag on main as the commit it points at', () => {
    expect(decideGuard(inputs({}))).toEqual({
      kind: 'accept',
      sha: MAIN_COMMIT,
      baseUrl: APP,
      label: 'staging-20260928-release-1',
    });
  });

  it('accepts a SHA on main, and main HEAD itself', () => {
    const decision = decideGuard(inputs({ ref: MAIN_COMMIT, compareStatus: 'identical' }));
    expect(decision).toMatchObject({ kind: 'accept', sha: MAIN_COMMIT });
  });

  it('refuses a tag that points off main', () => {
    for (const compareStatus of ['ahead', 'diverged', 'missing'] as const) {
      expect(decideGuard(inputs({ compareStatus }))).toEqual({
        kind: 'refuse',
        reason: 'the suite commit is not on main',
      });
    }
  });

  it('gives its own reason for no tag and for a tag on a tree or a blob', () => {
    expect(decideGuard(inputs({ commit: { kind: 'no-tag' } }))).toEqual({
      kind: 'refuse',
      reason: 'ref names no staging release tag',
    });
    expect(decideGuard(inputs({ commit: { kind: 'not-a-commit' } }))).toEqual({
      kind: 'refuse',
      reason: 'the tag does not point at a commit',
    });
    expect(decideGuard(inputs({ commit: { kind: 'commit', sha: 'not-a-sha' } })).kind).toBe(
      'refuse'
    );
  });

  it('refuses a branch or a pull request ref, and names neither', () => {
    for (const refused of ['feature-branch', 'refs/pull/12/merge', '::warning::x']) {
      const decision = decideGuard(inputs({ ref: refused }));
      expect(decision.kind).toBe('refuse');
      if (decision.kind === 'refuse') expect(decision.reason).not.toContain(refused);
    }
  });

  it('takes the staging app URL as the default, and refuses any other URL', () => {
    expect(decideGuard(inputs({ baseUrl: APP }))).toMatchObject({ kind: 'accept', baseUrl: APP });
    expect(decideGuard(inputs({ baseUrl: 'https://other.example' }))).toMatchObject({
      kind: 'refuse',
      reason: 'base-url must be the staging app URL, the STAGING_APP_URL variable',
    });
  });

  it('refuses when the staging app URL variable is not set', () => {
    expect(decideGuard(inputs({ expectedUrl: '' }))).toMatchObject({ kind: 'refuse' });
  });
});

describe('the tag resolve', () => {
  const TAG = 'staging-20260928-release-1';

  it('gives the commit of a lightweight tag', async () => {
    const { gh } = api({ [`git/ref/tags/${TAG}`]: ref('commit', MAIN_COMMIT) });
    expect(await tagCommit(gh, TAG)).toEqual({ kind: 'commit', sha: MAIN_COMMIT });
  });

  it('follows an annotated tag to its commit', async () => {
    const { gh } = api({
      [`git/ref/tags/${TAG}`]: ref('tag', TAG_OBJECT),
      [`git/tags/${TAG_OBJECT}`]: ref('commit', MAIN_COMMIT),
    });
    expect(await tagCommit(gh, TAG)).toEqual({ kind: 'commit', sha: MAIN_COMMIT });
  });

  it('tells a tag on a tree or a blob from a missing tag', async () => {
    for (const type of ['tree', 'blob']) {
      const { gh } = api({ [`git/ref/tags/${TAG}`]: ref(type, MAIN_COMMIT) });
      expect(await tagCommit(gh, TAG)).toEqual({ kind: 'not-a-commit' });
    }
    expect(await tagCommit(api({}).gh, TAG)).toEqual({ kind: 'no-tag' });
  });

  it('stops after four annotated tags in a chain', async () => {
    const { gh, paths } = api({
      [`git/ref/tags/${TAG}`]: ref('tag', TAG_OBJECT),
      [`git/tags/${TAG_OBJECT}`]: ref('tag', TAG_OBJECT),
    });
    expect(await tagCommit(gh, TAG)).toEqual({ kind: 'not-a-commit' });
    expect(paths).toHaveLength(5);
  });

  it('fails on an API answer that is not 200 or 404', async () => {
    const { gh } = api({ [`git/ref/tags/${TAG}`]: { status: 500, body: null } });
    await expect(tagCommit(gh, TAG)).rejects.toThrow('answered 500');
  });
});

describe('the compare to main', () => {
  it('resolves main by its branch ref, so a tag named main cannot stand in', async () => {
    const { gh, paths } = api({
      'git/ref/heads/main': ref('commit', MAIN_COMMIT),
      'git/ref/tags/main': ref('commit', OFF_MAIN),
    });
    expect(await mainCommit(gh)).toBe(MAIN_COMMIT);
    expect(paths).toEqual(['git/ref/heads/main']);
    await expect(mainCommit(api({}).gh)).rejects.toThrow('refs/heads/main');
  });

  it('compares from the main SHA, and maps every other answer to missing', async () => {
    for (const status of ['identical', 'behind', 'ahead', 'diverged'] as const) {
      const { gh, paths } = api({
        [`compare/${MAIN_COMMIT}...${OFF_MAIN}`]: { body: { status } },
      });
      expect(await compareStatus(gh, MAIN_COMMIT, OFF_MAIN)).toBe(status);
      expect(paths).toEqual([`compare/${MAIN_COMMIT}...${OFF_MAIN}`]);
    }
    const odd = api({ [`compare/${MAIN_COMMIT}...${OFF_MAIN}`]: { body: { status: 'other' } } });
    expect(await compareStatus(odd.gh, MAIN_COMMIT, OFF_MAIN)).toBe('missing');
    expect(await compareStatus(api({}).gh, MAIN_COMMIT, OFF_MAIN)).toBe('missing');
  });
});
