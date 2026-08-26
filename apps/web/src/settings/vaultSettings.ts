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

export interface VaultSettingsForm {
  pinMode: PinMode;
  byoEndpoint: string;
  byoKind: ByoKind;
  byoAccessToken: string;
  /** Newest-n retention; blank keeps every version within quota. */
  keepLatestVersions: string;
}

export const DEFAULT_VAULT_SETTINGS_FORM: VaultSettingsForm = {
  pinMode: 'hosted',
  byoEndpoint: '',
  byoKind: 'kubo',
  byoAccessToken: '',
  keepLatestVersions: '',
};

export type VaultSettingsDraft =
  | { ok: true; settings: VaultSettingsDescriptor }
  | { ok: false; problem: string };

/**
 * Builds the descriptor for one save. Called per dispatch, never cached: the
 * bearer rides a transferable buffer that `saveVaultSettings` detaches, so a
 * descriptor sent twice would carry a spent credential the second time.
 */
export function buildVaultSettings(form: VaultSettingsForm): VaultSettingsDraft {
  const keep = retention(form.keepLatestVersions);
  if (keep === 'invalid') {
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
      keepLatestVersions: keep,
    },
  };
}

/**
 * The bearer as a buffer of its own, so the transfer moves it out of this realm.
 * Copied into an exactly-sized one rather than handing over the encoder's
 * backing store, which a pooled allocation would make larger than the token.
 */
function bearer(token: string): ArrayBuffer | null {
  if (token === '') return null;
  const encoded = new TextEncoder().encode(token);
  const buffer = new ArrayBuffer(encoded.byteLength);
  new Uint8Array(buffer).set(encoded);
  return buffer;
}

function retention(value: string): number | null | 'invalid' {
  const trimmed = value.trim();
  if (trimmed === '') return null;
  if (!/^\d+$/.test(trimmed)) return 'invalid';
  return Number(trimmed);
}
