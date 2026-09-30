import { describe, expect, it } from 'vitest';
import { decideGuard, newestStagingTag, refShape, type GuardInputs } from './guard';

const APP = 'https://app.example';
const MAIN_COMMIT = 'a'.repeat(40);

const inputs = (over: Partial<GuardInputs>): GuardInputs => ({
  ref: 'staging-20260928-release-1',
  baseUrl: '',
  expectedUrl: APP,
  tagCommit: MAIN_COMMIT,
  compareStatus: 'behind',
  ...over,
});

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
    for (const ref of [
      'main',
      'refs/pull/12/merge',
      'staging-v0.26.2-rc-1',
      'aaaa',
      'staging-x;y',
    ]) {
      expect(refShape(ref)).toBe('refused');
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
    const decision = decideGuard(
      inputs({ ref: MAIN_COMMIT, tagCommit: null, compareStatus: 'identical' })
    );
    expect(decision).toMatchObject({ kind: 'accept', sha: MAIN_COMMIT });
  });

  it('refuses a tag that points off main', () => {
    for (const compareStatus of ['ahead', 'diverged', 'missing']) {
      expect(decideGuard(inputs({ compareStatus }))).toEqual({
        kind: 'refuse',
        reason: 'the suite commit is not on main',
      });
    }
  });

  it('refuses a tag that does not exist, or that resolves to no commit', () => {
    expect(decideGuard(inputs({ tagCommit: null })).kind).toBe('refuse');
    expect(decideGuard(inputs({ tagCommit: 'not-a-sha' })).kind).toBe('refuse');
  });

  it('refuses a branch or a pull request ref, and names neither', () => {
    for (const ref of ['feature-branch', 'refs/pull/12/merge', '::warning::x']) {
      const decision = decideGuard(inputs({ ref }));
      expect(decision.kind).toBe('refuse');
      if (decision.kind === 'refuse') expect(decision.reason).not.toContain(ref);
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
