import { describe, expect, it } from 'vitest';

import { shortAccountId } from './format';

describe('shortAccountId', () => {
  it('takes both ends of a real account id, so two are told apart', () => {
    const shared = 'ab'.repeat(32);
    const first = shortAccountId(`${shared}-${'cd'.repeat(32)}`);
    const second = shortAccountId(`${shared}-${'ef'.repeat(32)}`);

    expect(first).toBe('ababab…cdcd');
    expect(first).not.toBe(second);
  });

  it('leaves an id no longer than the elision it would apply', () => {
    expect(shortAccountId('acct01')).toBe('acct01');
  });
});
