import { describe, expect, it } from 'vitest';
import { collectedMethods } from '@cipherbox/login';
import { desktopCollector } from './collector';

describe('the shell collector', () => {
  it('offers Google and email, in that order', () => {
    expect(collectedMethods(desktopCollector('a-google-client'))).toEqual(['google', 'email']);
  });

  it('has no wallet member at all, so no wallet method is offered', () => {
    const collector = desktopCollector('a-google-client');
    expect('wallet' in collector).toBe(false);
    expect(collectedMethods(collector)).not.toContain('wallet');
  });

  it('omits Google when the build carries no client ID', () => {
    expect(collectedMethods(desktopCollector(undefined))).toEqual(['email']);
  });

  it('hands the email answer straight to the sequencing', async () => {
    const answer = { email: 'member@example.com', code: '123456' };
    await expect(desktopCollector(undefined).email?.(answer)).resolves.toEqual(answer);
  });
});
