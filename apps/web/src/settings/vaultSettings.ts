/**
 * The vault settings form's fields, and the descriptor a save publishes from
 * them (`CONTEXT.md`, "Vault settings record").
 *
 * The endpoint and the bearer are checked by the engine, not here
 * (`validate_byo_config`): a second copy of those rules in the UI would be one
 * that drifts. What this owns is the shape — which fields make a provider, and
 * what an empty one means.
 */

import type { ByoKind, PinMode, VaultSettingsDescriptor } from '@cipherbox/client';

/**
 * The window a vault keeps before its owner chooses one, mirroring the engine
 * default. Only a form that has loaded no summary ever uses it.
 */
const DEFAULT_BIN_RETENTION_DAYS = 30;

export interface VaultSettingsFields {
  pinMode: PinMode;
  byoEndpoint: string;
  byoKind: ByoKind;
  byoAccessToken: string;
  /** Newest-n retention; blank keeps every version within quota. */
  keepLatestVersions: string;
  /**
   * Days a soft-deleted node stays in the bin. No control renders it yet, so
   * the form carries the loaded value untouched: a save replaces the whole
   * record, and a field this form drops is a choice the member loses.
   */
  binRetentionDays: number;
}

export const DEFAULT_VAULT_SETTINGS_FORM: VaultSettingsFields = {
  pinMode: 'hosted',
  byoEndpoint: '',
  byoKind: 'kubo',
  byoAccessToken: '',
  keepLatestVersions: '',
  binRetentionDays: DEFAULT_BIN_RETENTION_DAYS,
};

export type VaultSettingsDraft =
  | { ok: true; settings: VaultSettingsDescriptor }
  | { ok: false; problem: string };

/**
 * Builds the descriptor for one save. Called per dispatch, never cached: the
 * bearer rides a transferable buffer that `saveVaultSettings` detaches, so a
 * descriptor sent twice would carry a spent credential the second time.
 */
export function buildVaultSettings(form: VaultSettingsFields): VaultSettingsDraft {
  const keep = form.keepLatestVersions.trim();
  if (keep !== '' && !/^\d+$/.test(keep)) {
    return {
      ok: false,
      problem: 'keep-latest wants a whole number of versions, or nothing at all',
    };
  }
  const endpoint = form.byoEndpoint.trim();
  return {
    ok: true,
    settings: {
      pinMode: form.pinMode,
      byo:
        endpoint === ''
          ? null
          : { endpoint, kind: form.byoKind, accessToken: bearer(form.byoAccessToken) },
      keepLatestVersions: keep === '' ? null : Number(keep),
      binRetentionDays: form.binRetentionDays,
    },
  };
}

/** The bearer in a buffer of its own, so the send transfers it out of this realm. */
function bearer(token: string): ArrayBuffer | null {
  if (token === '') return null;
  return new TextEncoder().encode(token).buffer as ArrayBuffer;
}
