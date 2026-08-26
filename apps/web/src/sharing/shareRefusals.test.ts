import { describe, expect, it } from 'vitest';
import { refusalLabel } from './shareRefusals';

describe('how a share refusal reads to the member', () => {
  it('says a grant refusal in words, not as the engine’s check name', () => {
    expect(refusalLabel('grant-target-is-the-vault-root')).toContain('folder inside it');
  });

  it('says a link refusal in words, not as the engine’s check name', () => {
    expect(refusalLabel('invite-target-is-the-vault-root')).toContain('folder inside it');
  });

  it('falls back to the engine’s own name for a refusal it has no phrasing for', () => {
    expect(refusalLabel('some-rule-a-later-build-added')).toBe('some-rule-a-later-build-added');
  });
});
