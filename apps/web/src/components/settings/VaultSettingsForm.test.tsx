import { act, fireEvent, render, screen } from '@testing-library/react';
import type { VaultSettingsDescriptor } from '@cipherbox/client';
import { describe, expect, it, vi } from 'vitest';
import { VaultSettingsForm } from './VaultSettingsForm';
import { fakeCoreKitSession, fakeEngineClient, pageWrapper } from '../../test/authFakes';

/** Records what a save carried, and what the engine answered it with. */
function engineTaking(refusal?: Error) {
  const engine = fakeEngineClient();
  const saves: VaultSettingsDescriptor[] = [];
  const facade = engine.client.facade as unknown as {
    saveVaultSettings(settings: VaultSettingsDescriptor): Promise<unknown>;
  };
  facade.saveVaultSettings = vi.fn((settings: VaultSettingsDescriptor) => {
    saves.push(settings);
    return refusal === undefined ? Promise.resolve({ kind: 'done' }) : Promise.reject(refusal);
  });
  return { engine, saves };
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

const save = () => act(async () => void fireEvent.click(screen.getByTestId('settings-save')));

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

  it('never sends a retention the descriptor cannot carry', async () => {
    const taking = renderForm();

    type('keep newest versions', 'lots');
    await save();

    expect(taking.saves).toEqual([]);
    expect(screen.getByTestId('settings-error')).toBeTruthy();
  });
});
