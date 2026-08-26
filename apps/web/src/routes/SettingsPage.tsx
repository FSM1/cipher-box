import { useState } from 'react';
import { RecoveryPhraseSetup } from '../components/auth/RecoveryPhraseSetup';
import { AppShell } from '../components/layout/AppShell';
import { ForgetDeviceDialog } from '../components/settings/ForgetDeviceDialog';
import { VaultSettingsForm } from '../components/settings/VaultSettingsForm';
import { useEngineAccount } from '../engine/useEngineSession';
import { useAuthState } from '../stores/auth.store';

/** Which dialog the route has raised, if any. */
type Raised = 'recovery' | 'forget' | null;

/**
 * Account and vault settings, behind `RequireAuth` (blueprint/web-client.md
 * "Composition"). The route shell: sign-in identity, the recovery phrase, BYO
 * pinning and vault settings, and forget-this-device. Linking login methods and
 * the MFA/device-approval surface land here with their own scope.
 */
export function SettingsPage() {
  const account = useEngineAccount();
  const { email, method, recoveryEnrolled } = useAuthState();
  const [raised, setRaised] = useState<Raised>(null);

  return (
    <AppShell>
      <div className="settings-page" data-testid="settings-page">
        <h2 className="settings-heading">settings</h2>

        <section className="settings-section" data-testid="settings-account">
          <h3>account</h3>
          <dl className="settings-facts">
            <dt>signed in with</dt>
            <dd data-testid="settings-method">{method ?? 'unknown'}</dd>
            <dt>address</dt>
            {/* Wallet logins carry no email, as in the header menu. */}
            <dd data-testid="settings-email">{email ?? '[an0n]'}</dd>
            <dt>account</dt>
            <dd data-testid="settings-account-id">{account ?? 'checking session...'}</dd>
          </dl>
        </section>

        <section className="settings-section" data-testid="settings-recovery">
          <h3>recovery phrase</h3>
          <p className="settings-note">
            the one export that opens this account without any device it is enrolled on. shown once,
            at enrollment.
          </p>
          {recoveryEnrolled ? (
            <p className="settings-ok" data-testid="settings-recovery-on">
              {'// recovery phrase on'}
            </p>
          ) : (
            <button
              type="button"
              className="terminal-btn"
              onClick={() => setRaised('recovery')}
              data-testid="settings-recovery-setup"
            >
              set up recovery phrase
            </button>
          )}
        </section>

        <section className="settings-section" data-testid="settings-vault">
          <h3>storage</h3>
          <VaultSettingsForm />
        </section>

        <section
          className="settings-section settings-section--danger"
          data-testid="settings-device"
        >
          <h3>this device</h3>
          <p className="settings-note">
            signing out leaves this browser&apos;s cached blocks, queued uploads and staged bytes in
            place. forgetting the device erases them.
          </p>
          <button
            type="button"
            className="terminal-btn terminal-btn--danger"
            onClick={() => setRaised('forget')}
            data-testid="settings-forget-device"
          >
            forget this device
          </button>
        </section>
      </div>

      {raised === 'recovery' && <RecoveryPhraseSetup onClose={() => setRaised(null)} />}
      {raised === 'forget' && <ForgetDeviceDialog onClose={() => setRaised(null)} />}
    </AppShell>
  );
}
