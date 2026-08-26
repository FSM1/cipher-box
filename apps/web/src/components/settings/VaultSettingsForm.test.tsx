import { act, fireEvent, render, screen } from '@testing-library/react';
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

function renderForm(taking = engineTaking()) {
  const Providers = pageWrapper(
    taking.engine.client,
    fakeCoreKitSession({ loggedIn: true }).session
  );
  render(
    <Providers>
      <VaultSettingsForm />
    </Providers>
  );
  return taking;
}

const type = (label: RegExp | string, value: string) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value } });

const ack = () => screen.getByLabelText(/replaces every stored setting/) as HTMLInputElement;

const acknowledge = () => fireEvent.click(ack());

const saveButton = () => screen.getByTestId('settings-save') as HTMLButtonElement;

const save = () => {
  acknowledge();
  return act(async () => void fireEvent.click(saveButton()));
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
