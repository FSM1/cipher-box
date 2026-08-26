import { describe, expect, it } from 'vitest';
import {
  buildVaultSettings,
  DEFAULT_VAULT_SETTINGS_FORM,
  type VaultSettingsForm,
} from './vaultSettings';

const form = (overrides: Partial<VaultSettingsForm> = {}): VaultSettingsForm => ({
  ...DEFAULT_VAULT_SETTINGS_FORM,
  ...overrides,
});

/** The draft's settings, or a failure naming what the assertion expected. */
function settings(draft: ReturnType<typeof buildVaultSettings>) {
  if (!draft.ok) throw new Error(`expected a publishable draft, got: ${draft.problem}`);
  return draft.settings;
}

describe('the vault settings a save publishes', () => {
  it('names no provider until an endpoint is given', () => {
    expect(settings(buildVaultSettings(form())).byo).toBeNull();
  });

  it('reads a blank endpoint the same as an absent one, whitespace and all', () => {
    expect(settings(buildVaultSettings(form({ byoEndpoint: '   ' }))).byo).toBeNull();
  });

  it('carries the provider the member named, trimmed', () => {
    const built = settings(
      buildVaultSettings(
        form({ pinMode: 'external', byoEndpoint: ' https://kubo.example ', byoKind: 'psa' })
      )
    );

    expect(built.pinMode).toBe('external');
    expect(built.byo?.endpoint).toBe('https://kubo.example');
    expect(built.byo?.kind).toBe('psa');
  });

  it('carries a bearer as a transferable buffer, never a string', () => {
    const built = settings(
      buildVaultSettings(form({ byoEndpoint: 'https://kubo.example', byoAccessToken: 'opaque' }))
    );

    expect(built.byo?.accessToken).toBeInstanceOf(ArrayBuffer);
    expect(built.byo?.accessToken?.byteLength).toBe('opaque'.length);
  });

  it('mints a fresh bearer buffer per build, because the send detaches it', () => {
    const fields = form({ byoEndpoint: 'https://kubo.example', byoAccessToken: 'opaque' });

    const first = settings(buildVaultSettings(fields)).byo?.accessToken;
    const second = settings(buildVaultSettings(fields)).byo?.accessToken;

    expect(first).not.toBe(second);
  });

  it('leaves a provider that needs no bearer without one', () => {
    const built = settings(buildVaultSettings(form({ byoEndpoint: 'http://127.0.0.1:5001' })));

    expect(built.byo?.accessToken).toBeNull();
  });

  it('keeps every version when no retention is asked for', () => {
    expect(settings(buildVaultSettings(form())).keepLatestVersions).toBeNull();
  });

  it('carries a retention cap the member typed', () => {
    expect(
      settings(buildVaultSettings(form({ keepLatestVersions: ' 5 ' }))).keepLatestVersions
    ).toBe(5);
  });

  it('refuses a retention that is not a count, rather than sending one', () => {
    const draft = buildVaultSettings(form({ keepLatestVersions: 'lots' }));

    expect(draft.ok).toBe(false);
  });

  it('leaves the range of a well-formed count to the engine', () => {
    expect(settings(buildVaultSettings(form({ keepLatestVersions: '0' }))).keepLatestVersions).toBe(
      0
    );
  });
});
