import { describe, expect, it, vi } from 'vitest';
import { collectedMethods } from '@cipherbox/login';
import { invoke } from '@tauri-apps/api/core';
import { desktopCollector } from './collector';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));

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
    expect('google' in desktopCollector(undefined)).toBe(false);
    expect(collectedMethods(desktopCollector(undefined))).toEqual(['email']);
  });

  it('asks the shell for the ID token, naming the build client ID', async () => {
    vi.mocked(invoke).mockResolvedValue('an-id-token');
    await expect(desktopCollector('a-google-client').google?.(undefined)).resolves.toBe(
      'an-id-token'
    );
    expect(invoke).toHaveBeenCalledWith('collect_google_id_token', {
      clientId: 'a-google-client',
    });
  });

  it('hands the email answer straight to the sequencing', async () => {
    const answer = { email: 'member@example.com', code: '123456' };
    await expect(desktopCollector(undefined).email?.(answer)).resolves.toEqual(answer);
  });
});
