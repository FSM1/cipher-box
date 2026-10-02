import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { EngineRequestError, type RegisteredDeviceDescriptor } from '@cipherbox/client';
import { authStore } from '../../stores/auth.store';
import {
  authWrapper,
  FAKE_DEVICE_PUBLIC_KEY,
  FAKE_IDENTITY_TOKEN,
  fakeCoreKitSession,
  fakeEngineClient,
  fakeSignatureOver,
  type EngineCalls,
} from '../../test/authFakes';
import { DeviceKeyUnusableError } from '../../auth/deviceIdentity';
import { DevicesPane } from './DevicesPane';

const OTHER = {
  id: 'device-other',
  publicKey: 'bb'.repeat(32),
  label: 'the laptop',
  createdAt: '2026-08-01T09:00:00.000Z',
  lastSeenAt: '2026-08-20T09:00:00.000Z',
} satisfies RegisteredDeviceDescriptor;

const OWN = {
  id: 'device-own',
  publicKey: FAKE_DEVICE_PUBLIC_KEY,
  label: null,
  createdAt: '2026-08-02T09:00:00.000Z',
  lastSeenAt: '2026-08-21T09:00:00.000Z',
} satisfies RegisteredDeviceDescriptor;

/** The bytes the fake engine serves as a registration challenge. */
const CHALLENGE = Uint8Array.from([0xc0, 0xde]);

/** Mounts the pane over an account holding `listed`, and lets its read land. */
async function pane(...listed: RegisteredDeviceDescriptor[][]): Promise<EngineCalls> {
  const reads = [...listed];
  const engine = fakeEngineClient({
    devices: () => Promise.resolve(reads.length > 1 ? (reads.shift() ?? []) : (reads[0] ?? [])),
  });
  const session = fakeCoreKitSession({ loggedIn: true }).session;
  render(<DevicesPane />, { wrapper: authWrapper(engine.client, session) });
  await act(async () => undefined);
  return engine.calls;
}

const rows = () => screen.queryAllByTestId('settings-device-row');

describe('the authorized devices pane', () => {
  beforeEach(() => authStore.signedOut());

  it('lists one row per registered key', async () => {
    await pane([OTHER, OWN]);

    await waitFor(() => expect(rows()).toHaveLength(2));
    expect(rows()[0].textContent).toContain('the laptop');
    expect(rows()[0].textContent).toContain(OTHER.publicKey.slice(0, 12));
  });

  it('marks the row this browser signs as, and no other', async () => {
    await pane([OTHER, OWN]);

    await waitFor(() => expect(rows()).toHaveLength(2));
    const marked = screen.getAllByTestId('settings-device-own').map((cell) => cell.textContent);
    expect(marked).toEqual(['', 'this device']);
  });

  it('offers to register this browser while the account holds no key for it', async () => {
    await pane([OTHER]);

    await waitFor(() => expect(screen.getByTestId('settings-device-register')).toBeTruthy());
  });

  it('stops offering it once the account carries this browser', async () => {
    await pane([OWN]);

    await waitFor(() => expect(rows()).toHaveLength(1));
    expect(screen.queryByTestId('settings-device-register')).toBeNull();
  });

  it('registers by signing the challenge the engine cut for this key', async () => {
    const calls = await pane([], [OWN]);
    await waitFor(() => expect(screen.getByTestId('settings-device-register')).toBeTruthy());

    await act(async () => {
      fireEvent.click(screen.getByTestId('settings-device-register'));
    });

    expect(calls.registrationChallenges).toEqual([FAKE_DEVICE_PUBLIC_KEY]);
    expect(calls.registered).toEqual([
      {
        publicKey: FAKE_DEVICE_PUBLIC_KEY,
        signature: fakeSignatureOver(CHALLENGE),
        identityToken: FAKE_IDENTITY_TOKEN,
        label: null,
      },
    ]);
    // The re-read is what puts the new key in the list, so the offer retires.
    await waitFor(() => expect(screen.queryByTestId('settings-device-register')).toBeNull());
    expect(screen.getByTestId('settings-device-own').textContent).toBe('this device');
  });

  it('asks before it revokes, and revokes nothing until the member confirms', async () => {
    const calls = await pane([OTHER]);
    await waitFor(() => expect(rows()).toHaveLength(1));

    await act(async () => {
      fireEvent.click(screen.getByTestId('settings-device-revoke'));
    });

    expect(screen.getByTestId('settings-device-revoke-dialog')).toBeTruthy();
    expect(calls.revoked).toEqual([]);
  });

  it('revokes the key the confirmed row named', async () => {
    const calls = await pane([OTHER, OWN]);
    await waitFor(() => expect(rows()).toHaveLength(2));

    await act(async () => {
      fireEvent.click(screen.getAllByTestId('settings-device-revoke')[0]);
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId('settings-device-revoke-confirm'));
    });

    expect(calls.revoked).toEqual([OTHER.id]);
  });

  // Every row carries the same destructive control, so a name that omits the
  // device leaves a reader unable to tell the rows apart, and confirms a revoke
  // that named nothing.
  it('names the device in the revoke control and in the confirmation', async () => {
    await pane([OTHER, OWN]);
    await waitFor(() => expect(rows()).toHaveLength(2));

    const [first, second] = screen
      .getAllByTestId('settings-device-revoke')
      .map((control) => control.getAttribute('aria-label'));
    expect(first).not.toBe(second);
    expect(first).toContain(OTHER.publicKey.slice(0, 12));

    await act(async () => {
      fireEvent.click(screen.getAllByTestId('settings-device-revoke')[0]);
    });

    expect(screen.getByTestId('settings-device-revoke-named').textContent).toContain(
      OTHER.publicKey.slice(0, 12)
    );
  });

  // The affordance and the truth agree (ADR 0009 consequence 5): a registration
  // signs the identity token of this sign-in, so a restored session cannot run
  // one and the control says so instead of failing when it is pressed.
  it('closes the register control when this sign-in carries no identity token', async () => {
    const engine = fakeEngineClient({ devices: () => Promise.resolve([]) });
    const session = fakeCoreKitSession({ loggedIn: true, identityToken: null }).session;
    render(<DevicesPane />, { wrapper: authWrapper(engine.client, session) });
    await act(async () => undefined);
    const register = await waitFor(() => screen.getByTestId('settings-device-register'));

    expect(register.getAttribute('disabled')).not.toBeNull();
    expect(register.getAttribute('aria-label')).toContain('sign in again');
    expect(screen.getByTestId('settings-device-register-closed').textContent).toBe(
      'sign in again with "save this device" checked'
    );

    await act(async () => {
      fireEvent.click(register);
    });

    expect(engine.calls.registered).toEqual([]);
  });

  // A registration spends the token of this sign-in, so after a revoke the
  // control asks for a fresh sign-in rather than fail against the API.
  it('closes the register control once a registration has spent the token', async () => {
    const calls = await pane([], [OWN], []);
    await waitFor(() => expect(screen.getByTestId('settings-device-register')).toBeTruthy());
    await act(async () => {
      fireEvent.click(screen.getByTestId('settings-device-register'));
    });
    await waitFor(() => expect(rows()).toHaveLength(1));

    await act(async () => {
      fireEvent.click(screen.getByTestId('settings-device-revoke'));
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId('settings-device-revoke-confirm'));
    });

    const register = await waitFor(() => screen.getByTestId('settings-device-register'));
    expect(register.getAttribute('disabled')).not.toBeNull();
    expect(register.getAttribute('aria-label')).toContain('sign in again');
    await act(async () => {
      fireEvent.click(register);
    });
    expect(calls.registered).toHaveLength(1);
  });

  // `forgetDevice` leaves the session holding no key. Keeping the last answer
  // would mark a listed row as this device and hide the way back in.
  it('unmarks the row and names the missing key once this browser holds none', async () => {
    const engine = fakeEngineClient({ devices: () => Promise.resolve([OWN]) });
    const session = fakeCoreKitSession({ loggedIn: true, noDeviceIdentity: true }).session;
    render(<DevicesPane />, { wrapper: authWrapper(engine.client, session) });
    await act(async () => undefined);

    await waitFor(() => expect(rows()).toHaveLength(1));
    expect(screen.getByTestId('settings-device-own').textContent).toBe('');
    expect(screen.getByTestId('settings-device-register').getAttribute('disabled')).not.toBeNull();
    expect(screen.getByTestId('settings-device-register-closed').textContent).toBe(
      'this browser holds no device identity key; sign in again to create one'
    );
  });

  // A sign-in cannot give a browser a key its WebCrypto cannot hold, so the
  // pane names the browser as the cause instead.
  it('names an unusable device key as the cause, not the sign-in', async () => {
    const unusable = new DeviceKeyUnusableError().message;
    const engine = fakeEngineClient({ devices: () => Promise.resolve([]) });
    const session = fakeCoreKitSession({ loggedIn: true, deviceKeyUnusable: true }).session;
    render(<DevicesPane />, { wrapper: authWrapper(engine.client, session) });
    await act(async () => undefined);

    const register = await waitFor(() => screen.getByTestId('settings-device-register'));
    await waitFor(() =>
      expect(screen.getByTestId('settings-device-register-closed').textContent).toBe(unusable)
    );
    expect(register.getAttribute('disabled')).not.toBeNull();
    expect(register.getAttribute('title')).toBe(unusable);
  });

  it('closes the control once the API refuses this sign-in as unauthorized', async () => {
    const engine = fakeEngineClient({
      devices: () => Promise.resolve([]),
      registerDevice: () =>
        Promise.reject(new EngineRequestError('auth error: refused as unauthorized', 'auth')),
    });
    const session = fakeCoreKitSession({ loggedIn: true }).session;
    render(<DevicesPane />, { wrapper: authWrapper(engine.client, session) });
    await act(async () => undefined);
    const register = await waitFor(() => screen.getByTestId('settings-device-register'));
    await waitFor(() => expect(register.getAttribute('disabled')).toBeNull());

    await act(async () => {
      fireEvent.click(register);
    });

    expect(register.getAttribute('disabled')).not.toBeNull();
    expect(screen.getByTestId('settings-device-register-closed').textContent).toContain(
      'can no longer register a device'
    );
    // The reason line names the cause; the engine's own line would repeat it.
    expect(screen.queryByTestId('settings-devices-error')).toBeNull();
    for (const said of [register.getAttribute('title'), register.getAttribute('aria-label')]) {
      expect(said).not.toContain(FAKE_IDENTITY_TOKEN);
    }
    await act(async () => {
      fireEvent.click(register);
    });
    expect(engine.calls.registered).toHaveLength(1);
  });

  it('marks this device when a refused registration finds its key already listed', async () => {
    const reads = [[], [OWN]];
    const engine = fakeEngineClient({
      devices: () => Promise.resolve(reads.length > 1 ? (reads.shift() ?? []) : reads[0]),
      registerDevice: () =>
        Promise.reject(new EngineRequestError('auth error: refused as unauthorized', 'auth')),
    });
    const session = fakeCoreKitSession({ loggedIn: true }).session;
    render(<DevicesPane />, { wrapper: authWrapper(engine.client, session) });
    await act(async () => undefined);
    const register = await waitFor(() => screen.getByTestId('settings-device-register'));
    await waitFor(() => expect(register.getAttribute('disabled')).toBeNull());

    await act(async () => {
      fireEvent.click(register);
    });

    await waitFor(() =>
      expect(screen.getByTestId('settings-device-own').textContent).toBe('this device')
    );
    expect(screen.queryByTestId('settings-device-register')).toBeNull();
    expect(screen.queryByTestId('settings-devices-error')).toBeNull();
  });

  it('shows no closed reason while it still reads this browser key', async () => {
    const engine = fakeEngineClient({ devices: () => Promise.resolve([]) });
    const coreKit = fakeCoreKitSession({ loggedIn: true, identityToken: null });
    const identity = coreKit.session.deviceIdentity();
    if (identity) identity.publicKeyHex = () => new Promise(() => undefined);
    render(<DevicesPane />, { wrapper: authWrapper(engine.client, coreKit.session) });
    await act(async () => undefined);

    const register = await waitFor(() => screen.getByTestId('settings-device-register'));
    expect(register.getAttribute('disabled')).not.toBeNull();
    expect(screen.queryByTestId('settings-device-register-closed')).toBeNull();
  });
});
