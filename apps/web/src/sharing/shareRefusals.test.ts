import { describe, expect, it } from 'vitest';
import { refusalLabel } from './shareRefusals';

describe('how a share refusal reads to the member', () => {
  it('says a grant refusal in words, not as the engine’s check name', () => {
    expect(refusalLabel('grant-target-is-the-vault-root')).toContain('folder inside it');
  });

  it('says a link refusal in words, not as the engine’s check name', () => {
    expect(refusalLabel('invite-target-is-the-vault-root')).toContain('folder inside it');
  });

  it('says a refusal the engine raises over a scope it will not resume in words', () => {
    expect(refusalLabel('resume-not-this-grant')).toContain('no second one');
  });

  it('names an edit of a standing grant the engine refused', () => {
    expect(refusalLabel('grant-recipient-already-has-access')).toContain('already has');
    expect(refusalLabel('grant-recipient-not-granted')).toContain('no grant');
    expect(refusalLabel('grant-row-is-a-link')).toContain('mint a new one');
  });

  it('names a contact whose key changed and a revoke that named no link', () => {
    expect(refusalLabel('grant-recipient-key-changed')).toContain('share again');
    expect(refusalLabel('link-ambiguous')).toContain('more than one link');
  });

  it('falls back to the engine’s own name for a refusal it has no phrasing for', () => {
    expect(refusalLabel('some-rule-a-later-build-added')).toBe('some-rule-a-later-build-added');
  });

  it('reads a name that collides with a prototype key as itself', () => {
    expect(refusalLabel('constructor')).toBe('constructor');
    expect(refusalLabel('__proto__')).toBe('__proto__');
  });
});
