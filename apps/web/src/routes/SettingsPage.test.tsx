import { act, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SettingsPage } from './SettingsPage';
import { authStore } from '../stores/auth.store';
import { fakeCoreKitSession, fakeEngineClient, pageWrapper } from '../test/authFakes';

function renderSettings(engine = fakeEngineClient()) {
  const Providers = pageWrapper(engine.client, fakeCoreKitSession({ loggedIn: true }).session);
  render(
    <Providers>
      <MemoryRouter initialEntries={['/settings']}>
        <SettingsPage />
      </MemoryRouter>
    </Providers>
  );
  return engine;
}

/** Opens a dialog and lets the render its state change drives settle. */
async function open(testId: string) {
  await act(async () => {
    fireEvent.click(screen.getByTestId(testId));
  });
}

afterEach(() => authStore.signedOut());

describe('the settings route', () => {
  it('names how this session was established', () => {
    authStore.signedIn('google', 'user@example.test');
    renderSettings();

    expect(screen.getByTestId('settings-method').textContent).toBe('google');
    expect(screen.getByTestId('settings-email').textContent).toBe('user@example.test');
  });

  it('names a session that carries no email, as a wallet login does', () => {
    authStore.signedIn('wallet', null);
    renderSettings();

    expect(screen.getByTestId('settings-email').textContent).toBe('[an0n]');
  });

  it('offers the recovery phrase while the account carries no factor policy', async () => {
    renderSettings();

    await open('settings-recovery-setup');

    expect(screen.getByTestId('recovery-setup-explain')).toBeTruthy();
  });

  it('stops offering it once the account carries one', () => {
    authStore.recoveryEnrollment(true);
    renderSettings();

    // Offering it again would enroll a second time over a live policy.
    expect(screen.queryByTestId('settings-recovery-setup')).toBeNull();
    expect(screen.getByTestId('settings-recovery-on')).toBeTruthy();
  });

  it('hosts the vault settings form', () => {
    renderSettings();

    expect(screen.getByTestId('vault-settings-form')).toBeTruthy();
  });

  it('asks before forgetting the device, and erases nothing until it is told to', async () => {
    const engine = renderSettings();
    const forget = vi.spyOn(engine.client.facade, 'forgetDevice');

    await open('settings-forget-device');

    expect(screen.getByTestId('forget-device-dialog')).toBeTruthy();
    expect(screen.getByTestId('forget-device-confirm').hasAttribute('disabled')).toBe(true);
    await open('forget-device-confirm');
    expect(forget).not.toHaveBeenCalled();
  });

  it('erases once the member acknowledges what it takes', async () => {
    const engine = renderSettings();
    const forget = vi.spyOn(engine.client.facade, 'forgetDevice');

    await open('settings-forget-device');
    await act(async () => {
      fireEvent.click(screen.getByLabelText(/this browser will be signed out/));
    });
    await open('forget-device-confirm');

    expect(forget).toHaveBeenCalledTimes(1);
  });
});
