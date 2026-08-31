import { act, fireEvent, render, screen } from '@testing-library/react';
import type { VaultSettingsSummaryDescriptor } from '@cipherbox/client';
import { describe, expect, it } from 'vitest';
import { VaultSettingsForm } from './VaultSettingsForm';
import { fakeCoreKitSession, fakeEngineClient, pageWrapper } from '../../test/authFakes';

/** Records what a save carried, and what the engine answered it with. */
function engineTaking(refusal?: Error) {
  const engine = fakeEngineClient(
    refusal === undefined ? {} : { saveVaultSettings: () => Promise.reject(refusal) }
  );
  return { engine, saves: engine.calls.vaultSettings };
}

function summary(
  overrides: Partial<VaultSettingsSummaryDescriptor> = {}
): VaultSettingsSummaryDescriptor {
  return {
    pinMode: 'hosted',
    byoEndpoint: null,
    byoKind: null,
    byoCredentialStored: false,
    keepLatestVersions: null,
    binRetentionDays: 30,
    origin: 'resolved',
    ...overrides,
  };
}

/** A vault whose published record names a provider and holds its bearer. */
const WITH_CREDENTIAL = summary({
  pinMode: 'dual',
  byoEndpoint: 'https://kubo.example',
  byoKind: 'kubo',
  byoCredentialStored: true,
});

function renderForm(taking = engineTaking(), stored: VaultSettingsSummaryDescriptor = summary()) {
  const Providers = pageWrapper(
    taking.engine.client,
    fakeCoreKitSession({ loggedIn: true }).session
  );
  render(
    <Providers>
      <VaultSettingsForm summary={stored} />
    </Providers>
  );
  return taking;
}

const type = (label: RegExp | string, value: string) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value } });

const ack = () => screen.getByLabelText(/replaces every stored setting/) as HTMLInputElement;

const acknowledge = () => fireEvent.click(ack());

const saveButton = () => screen.getByTestId('settings-save') as HTMLButtonElement;

/** Presses save without touching the acknowledgement, which a retry keeps. */
const attempt = () => act(async () => void fireEvent.click(saveButton()));

const save = () => {
  acknowledge();
  return attempt();
};

describe('the vault settings form', () => {
  it('publishes the placement, provider and retention as one command', async () => {
    const taking = renderForm();

    type('where versions are pinned', 'dual');
    type('your ipfs provider', 'https://kubo.example');
    type('provider api', 'psa');
    type('provider access token', 'opaque');
    type('keep newest versions', '5');
    await save();

    expect(taking.saves).toHaveLength(1);
    const sent = taking.saves[0];
    expect(sent.pinMode).toBe('dual');
    expect(sent.byo?.endpoint).toBe('https://kubo.example');
    expect(sent.byo?.kind).toBe('psa');
    expect(sent.keepLatestVersions).toBe(5);
    expect(screen.getByTestId('settings-saved')).toBeTruthy();
  });

  it('drops the bearer once the send has spent it, so a retry types it again', async () => {
    renderForm();

    type('your ipfs provider', 'https://kubo.example');
    type('provider access token', 'opaque');
    await save();

    expect((screen.getByLabelText('provider access token') as HTMLInputElement).value).toBe('');
  });

  it('renders the engine’s refusal in its own words', async () => {
    renderForm(engineTaking(new Error('unsupported target: byo-endpoint-insecure-transport')));

    type('your ipfs provider', 'http://kubo.example');
    await save();

    expect(screen.getByTestId('settings-error').textContent).toContain(
      'byo-endpoint-insecure-transport'
    );
    expect(screen.queryByTestId('settings-saved')).toBeNull();
  });

  it('leaves no readable bearer behind where the send never took the buffer', async () => {
    const taking = renderForm();

    type('your ipfs provider', 'https://kubo.example');
    type('provider access token', 'opaque');
    await save();

    // The fake takes the descriptor in-process rather than transferring it, so
    // the buffer is still this realm's to scrub — as a refused dispatch leaves it.
    const carried = taking.saves[0].byo?.accessToken;
    expect(new Uint8Array(carried!)).toEqual(new Uint8Array('opaque'.length));
  });

  it('scrubs the bearer the engine refused rather than leaving it in memory', async () => {
    const taking = renderForm(engineTaking(new Error('unsupported target: byo-endpoint-refused')));

    type('your ipfs provider', 'https://kubo.example');
    type('provider access token', 'opaque');
    await save();

    const carried = taking.saves[0].byo?.accessToken;
    expect(new Uint8Array(carried!)).toEqual(new Uint8Array('opaque'.length));
  });

  it('sends nothing until the member takes on replacing the whole record', () => {
    const taking = renderForm();

    type('keep newest versions', '5');

    expect(saveButton().disabled).toBe(true);
    fireEvent.click(saveButton());
    expect(taking.saves).toEqual([]);
  });

  it('asks for the acknowledgement again once a save has spent it', async () => {
    renderForm();

    type('keep newest versions', '5');
    await save();

    expect(ack().checked).toBe(false);
    expect(saveButton().disabled).toBe(true);
  });

  it('never sends a retention the descriptor cannot carry', async () => {
    const taking = renderForm();

    type('keep newest versions', 'lots');
    await save();

    expect(taking.saves).toEqual([]);
    expect(screen.getByTestId('settings-error')).toBeTruthy();
  });
});

describe('a save over a credential the form cannot show', () => {
  it('refuses to blank a stored credential as a side effect of an unrelated edit', async () => {
    const taking = renderForm(engineTaking(), WITH_CREDENTIAL);

    type('keep newest versions', '5');
    await save();

    expect(taking.saves).toEqual([]);
    expect(screen.getByTestId('settings-error').textContent).toMatch(/credential/i);
  });

  it('clears the stored credential where the member asks for exactly that', async () => {
    const taking = renderForm(engineTaking(), WITH_CREDENTIAL);

    fireEvent.click(screen.getByLabelText(/clear the stored provider credential/));
    await save();

    expect(taking.saves).toHaveLength(1);
    expect(taking.saves[0].byo?.accessToken).toBeNull();
  });

  it('takes a save that re-enters the credential', async () => {
    const taking = renderForm(engineTaking(), WITH_CREDENTIAL);

    type('provider access token', 'a fresh one');
    await save();

    expect(taking.saves).toHaveLength(1);
    expect(taking.saves[0].byo?.accessToken).not.toBeNull();
  });
});

describe('what the form says about where its values came from', () => {
  it('renders a resolved read as the member’s own published choice', () => {
    renderForm(engineTaking(), summary({ origin: 'resolved' }));

    expect(screen.queryByTestId('settings-origin-notice')).toBeNull();
    expect(screen.getByTestId('settings-credential-note')).toBeTruthy();
  });

  it('names a stale read as this device’s copy rather than the published record', () => {
    renderForm(engineTaking(), summary({ origin: 'stale' }));

    expect(screen.getByTestId('settings-origin-notice').textContent).toMatch(/this device/);
    expect(screen.getByTestId('settings-credential-note')).toBeTruthy();
  });

  it('says an unread record is nobody’s choice, and claims nothing about the credential', () => {
    renderForm(engineTaking(), summary({ origin: 'defaults' }));

    expect(screen.getByTestId('settings-origin-notice').textContent).toMatch(
      /nothing on this form is your stored choice/
    );
    // The claim is unknowable here: `defaults` reports a record nothing read.
    expect(screen.queryByTestId('settings-credential-note')).toBeNull();
  });

  it('publishes over an unread record only once that is taken on separately', async () => {
    const taking = renderForm(engineTaking(), summary({ origin: 'defaults' }));

    acknowledge();
    await attempt();
    expect(taking.saves).toEqual([]);
    expect(screen.getByTestId('settings-error').textContent).toMatch(/no settings record loaded/);

    fireEvent.click(screen.getByLabelText(/no settings record loaded/));
    await attempt();

    expect(taking.saves).toHaveLength(1);
  });
});
