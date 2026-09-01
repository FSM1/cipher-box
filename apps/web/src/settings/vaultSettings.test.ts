import { describe, expect, it } from 'vitest';
import {
  buildVaultSettings,
  DEFAULT_VAULT_SETTINGS_FORM,
  type VaultSettingsFields,
} from './vaultSettings';

const form = (overrides: Partial<VaultSettingsFields> = {}): VaultSettingsFields => ({
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

    const carried = built.byo?.accessToken;
    expect(carried?.byteLength).toBe('opaque'.length);
    expect(new TextDecoder().decode(new Uint8Array(carried!))).toBe('opaque');
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

  it.each([0, 7, 3650])('carries a bin retention of %i through a save', (days) => {
    expect(
      settings(buildVaultSettings(form({ binRetentionDays: String(days) }))).binRetentionDays
    ).toBe(days);
  });

  it('carries a bin retention the member typed with spaces around it', () => {
    expect(settings(buildVaultSettings(form({ binRetentionDays: ' 7 ' }))).binRetentionDays).toBe(
      7
    );
  });

  it.each(['', '   ', 'lots', '-1', '1.5'])(
    'refuses the bin retention %j rather than sending one',
    (binRetentionDays) => {
      expect(buildVaultSettings(form({ binRetentionDays })).ok).toBe(false);
    }
  );

  it('leaves the bar on a well-formed bin retention to the engine', () => {
    expect(settings(buildVaultSettings(form({ binRetentionDays: '4000' }))).binRetentionDays).toBe(
      4000
    );
  });
});
