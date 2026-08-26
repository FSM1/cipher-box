import { useState } from 'react';
import type { ByoKind, PinMode } from '@cipherbox/client';
import { useCommandRunner } from '../../hooks/useCommandRunner';
import {
  buildVaultSettings,
  DEFAULT_VAULT_SETTINGS_FORM,
  type VaultSettingsFields,
} from '../../settings/vaultSettings';

const PIN_MODES: { value: PinMode; label: string }[] = [
  { value: 'hosted', label: 'cipherbox only' },
  { value: 'external', label: 'my provider only' },
  { value: 'dual', label: 'both' },
];

const BYO_KINDS: { value: ByoKind; label: string }[] = [
  { value: 'kubo', label: 'kubo rpc' },
  { value: 'psa', label: 'pinning service api' },
  { value: 'pinata', label: 'pinata' },
];

/**
 * The member's placement, provider and retention choice, published as one
 * `saveVaultSettings` (blueprint/web-client.md "Composition").
 *
 * The form starts at the defaults every time, because the wasm boundary is
 * write-only by design — no getter reads a stored config back, so a saved bearer
 * never crosses into JS (`crates/wasm/src/lib.rs`). A save therefore replaces the
 * whole record with what is on the form, tearing down a provider the member
 * configured earlier and cannot see here — so it is gated on an acknowledgement.
 */
export function VaultSettingsForm() {
  const [fields, setFields] = useState<VaultSettingsFields>(DEFAULT_VAULT_SETTINGS_FORM);
  const [problem, setProblem] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const { busy, error, run } = useCommandRunner<'saveVaultSettings'>();
  const message = problem ?? error;

  const set = <K extends keyof VaultSettingsFields>(key: K, value: VaultSettingsFields[K]) => {
    setFields((current) => ({ ...current, [key]: value }));
    setSaved(false);
  };

  const save = () => {
    const draft = buildVaultSettings(fields);
    setProblem(draft.ok ? null : draft.problem);
    if (!draft.ok) return;
    void run('saveVaultSettings', (facade) => facade.saveVaultSettings(draft.settings)).then(
      (accepted) => {
        // The form is the bearer's terminal owner: a send transfers the buffer
        // out and detaches it, so a still-readable one never left this realm.
        const bearer = draft.settings.byo?.accessToken;
        if (bearer && bearer.byteLength > 0) new Uint8Array(bearer).fill(0);
        setSaved(accepted);
        // The bearer is spent by the send that carried it; a retry types it
        // again rather than re-sending a buffer this realm no longer owns.
        if (accepted) {
          setFields((current) => ({ ...current, byoAccessToken: '' }));
          setAcknowledged(false);
        }
      }
    );
  };

  return (
    <form
      className="settings-form"
      data-testid="vault-settings-form"
      onSubmit={(event) => {
        event.preventDefault();
        save();
      }}
    >
      <label className="settings-field" htmlFor="settings-pin-mode">
        <span>where versions are pinned</span>
        <select
          id="settings-pin-mode"
          className="dialog-input"
          value={fields.pinMode}
          onChange={(event) => set('pinMode', event.target.value as PinMode)}
        >
          {PIN_MODES.map((mode) => (
            <option key={mode.value} value={mode.value}>
              {mode.label}
            </option>
          ))}
        </select>
      </label>

      <label className="settings-field" htmlFor="settings-byo-endpoint">
        <span>your ipfs provider</span>
        <input
          id="settings-byo-endpoint"
          className="dialog-input"
          type="url"
          inputMode="url"
          autoComplete="off"
          placeholder="https://ipfs.example — leave blank to run none"
          value={fields.byoEndpoint}
          onChange={(event) => set('byoEndpoint', event.target.value)}
        />
      </label>

      <label className="settings-field" htmlFor="settings-byo-kind">
        <span>provider api</span>
        <select
          id="settings-byo-kind"
          className="dialog-input"
          value={fields.byoKind}
          onChange={(event) => set('byoKind', event.target.value as ByoKind)}
        >
          {BYO_KINDS.map((kind) => (
            <option key={kind.value} value={kind.value}>
              {kind.label}
            </option>
          ))}
        </select>
      </label>

      <label className="settings-field" htmlFor="settings-byo-token">
        <span>provider access token</span>
        <input
          id="settings-byo-token"
          className="dialog-input"
          type="password"
          autoComplete="off"
          spellCheck={false}
          placeholder="only if your provider needs one"
          value={fields.byoAccessToken}
          onChange={(event) => set('byoAccessToken', event.target.value)}
        />
      </label>

      <label className="settings-field" htmlFor="settings-retention">
        <span>keep newest versions</span>
        {/* Text, not `number`: an invalid `number` input reads back as blank,
            which here means "keep every version" — a different choice. */}
        <input
          id="settings-retention"
          className="dialog-input"
          type="text"
          inputMode="numeric"
          placeholder="blank keeps every version"
          value={fields.keepLatestVersions}
          onChange={(event) => set('keepLatestVersions', event.target.value)}
        />
      </label>

      <p className="sharing-note">
        {'// the engine never reads a saved provider credential back out, so nothing'}
        <br />
        {'// here is filled in from what you stored before.'}
      </p>

      <label className="recovery-ack" htmlFor="settings-replace-ack">
        <input
          id="settings-replace-ack"
          type="checkbox"
          checked={acknowledged}
          onChange={(event) => setAcknowledged(event.target.checked)}
        />
        <span>
          i understand saving replaces every stored setting with exactly what is on this form,
          including any provider i configured before
        </span>
      </label>

      <div className="settings-actions">
        <button
          type="submit"
          className="terminal-btn terminal-btn--filled"
          disabled={busy !== null || !acknowledged}
          data-testid="settings-save"
        >
          {busy !== null ? 'saving...' : 'save settings'}
        </button>
        {saved && (
          <span className="settings-ok" data-testid="settings-saved">
            {'// saved'}
          </span>
        )}
      </div>

      {message !== null && (
        <p className="dialog-error" role="alert" data-testid="settings-error">
          {message}
        </p>
      )}
    </form>
  );
}
