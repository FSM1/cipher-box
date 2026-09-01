import { useEffect, useState } from 'react';
import { originNotice, prefillFromSummary, settingsSaveVerdict } from '@cipherbox/client';
import type { ByoKind, PinMode, VaultSettingsSummaryDescriptor } from '@cipherbox/client';
import { useCommandRunner } from '../../hooks/useCommandRunner';
import {
  buildVaultSettings,
  DEFAULT_VAULT_SETTINGS_FORM,
  type VaultSettingsFields,
} from '../../settings/vaultSettings';

interface VaultSettingsFormProps {
  /**
   * What the storage read reported. Required: a save replaces the whole record,
   * so the refusals below are only guards while the origin and the stored-bearer
   * flag are the engine's answer rather than a stand-in for an absent read.
   */
  summary: VaultSettingsSummaryDescriptor;
  /** Re-reads the vault after a save, so the form shows what it now carries. */
  onSaved?: () => void;
}

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
 * Everything but the provider credential is read back and prefilled. The
 * credential is not: it is the one field the wasm boundary keeps write-only, so
 * a stored bearer never crosses into JS (`crates/wasm/src/lib.rs`). A save
 * replaces the whole record with what is on the form, so `settingsSaveVerdict`
 * refuses the two shapes that destroy a choice the member did not edit.
 */
export function VaultSettingsForm({ summary, onSaved }: VaultSettingsFormProps) {
  const [fields, setFields] = useState<VaultSettingsFields>(DEFAULT_VAULT_SETTINGS_FORM);
  const [problem, setProblem] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [clearCredential, setClearCredential] = useState(false);
  const [loadAcknowledged, setLoadAcknowledged] = useState(false);
  const { busy, error, run } = useCommandRunner<'saveVaultSettings'>();
  const message = problem ?? error;
  const origin = summary.origin;
  const notice = originNotice(origin);
  const credentialStored = summary.byoCredentialStored;

  // Each read the route lands refills the form, so a confirmed save shows what
  // the vault now carries rather than what was typed at it. The credential is
  // blanked rather than prefilled: no read can carry one. Every acknowledgement
  // clears with the refill: each one is taken on what the form held when it was
  // ticked, and the refill replaces values the form never shows.
  useEffect(() => {
    const { pinMode, byoEndpoint, byoKind, keepLatestVersions, binRetentionDays } =
      prefillFromSummary(summary);
    setFields({
      pinMode,
      byoEndpoint,
      byoKind,
      keepLatestVersions,
      binRetentionDays: String(binRetentionDays),
      byoAccessToken: '',
    });
    setAcknowledged(false);
    setClearCredential(false);
    setLoadAcknowledged(false);
  }, [summary]);

  const set = <K extends keyof VaultSettingsFields>(key: K, value: VaultSettingsFields[K]) => {
    setFields((current) => ({ ...current, [key]: value }));
    setSaved(false);
  };

  const save = () => {
    const verdict = settingsSaveVerdict({
      origin,
      credentialStored,
      byoEndpoint: fields.byoEndpoint,
      byoAccessToken: fields.byoAccessToken,
      clearCredential,
      loadAcknowledged,
    });
    if (!verdict.ok) {
      setProblem(verdict.problem);
      return;
    }
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
          setClearCredential(false);
          onSaved?.();
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
      {notice.note !== null && (
        <p className="settings-origin" role="status" data-testid="settings-origin-notice">
          {`// ${notice.note}`}
        </p>
      )}

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

      <label className="settings-field" htmlFor="settings-bin-retention">
        <span>days a deleted item is kept</span>
        <input
          id="settings-bin-retention"
          className="dialog-input"
          type="text"
          inputMode="numeric"
          value={fields.binRetentionDays}
          onChange={(event) => set('binRetentionDays', event.target.value)}
        />
      </label>

      <p className="sharing-note">{'// 0 deletes outright and keeps no bin'}</p>

      {/* A `defaults` load knows nothing about the record, so it can claim
          nothing about what the vault holds. */}
      {!notice.unread && (
        <p className="sharing-note" data-testid="settings-credential-note">
          {credentialStored
            ? '// a provider credential is stored. the engine never reads one back out,'
            : '// the engine never reads a provider credential back out,'}
          <br />
          {credentialStored
            ? '// so keeping the provider means typing it again — or clearing it outright.'
            : '// so this field is the only place one can be set.'}
        </p>
      )}

      {credentialStored && (
        <label className="recovery-ack" htmlFor="settings-clear-credential">
          <input
            id="settings-clear-credential"
            type="checkbox"
            checked={clearCredential}
            onChange={(event) => setClearCredential(event.target.checked)}
            data-testid="settings-clear-credential"
          />
          <span>clear the stored provider credential, leaving the provider with none</span>
        </label>
      )}

      {notice.unread && (
        <label className="recovery-ack" htmlFor="settings-defaults-ack">
          <input
            id="settings-defaults-ack"
            type="checkbox"
            checked={loadAcknowledged}
            onChange={(event) => setLoadAcknowledged(event.target.checked)}
            data-testid="settings-defaults-ack"
          />
          <span>
            i understand no settings record loaded, and that saving publishes these defaults over
            whatever the vault holds
          </span>
        </label>
      )}

      <label className="recovery-ack" htmlFor="settings-replace-ack">
        <input
          id="settings-replace-ack"
          type="checkbox"
          checked={acknowledged}
          onChange={(event) => setAcknowledged(event.target.checked)}
        />
        <span>
          i understand saving replaces every stored setting with exactly what is on this form,
          including the provider credential this form cannot show me
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
