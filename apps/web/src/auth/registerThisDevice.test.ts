import { EngineRequestError } from '@cipherbox/client';
import { describe, expect, it } from 'vitest';
import {
  FAKE_DEVICE_PUBLIC_KEY,
  FAKE_IDENTITY_TOKEN,
  fakeCoreKitSession,
  fakeEngineClient,
  fakeSignatureOver,
} from '../test/authFakes';
import { registerThisDevice } from './registerThisDevice';

/** The bytes the fake engine serves as a registration challenge. */
const CHALLENGE = Uint8Array.from([0xc0, 0xde]);

describe('registerThisDevice', () => {
  it('signs the challenge for this key with the token of this sign-in, then spends it', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession({ loggedIn: true });

    const publicKey = await registerThisDevice(coreKit.session, engine.client.facade);

    expect(publicKey).toBe(FAKE_DEVICE_PUBLIC_KEY);
    expect(engine.calls.registrationChallenges).toEqual([FAKE_DEVICE_PUBLIC_KEY]);
    expect(coreKit.calls.signed).toEqual([CHALLENGE]);
    expect(engine.calls.registered).toEqual([
      {
        publicKey: FAKE_DEVICE_PUBLIC_KEY,
        signature: fakeSignatureOver(CHALLENGE),
        identityToken: FAKE_IDENTITY_TOKEN,
        label: null,
      },
    ]);
    expect(coreKit.session.identityToken()).toBeNull();
  });

  it('dispatches nothing without the token of a fresh sign-in', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession({ loggedIn: true, identityToken: null });

    await expect(registerThisDevice(coreKit.session, engine.client.facade)).rejects.toThrow(
      'sign in again'
    );
    expect(engine.calls.registrationChallenges).toEqual([]);
  });

  it('drops a token the API refused as unauthorized', async () => {
    const refusal = new EngineRequestError('auth error: refused', 'auth');
    const engine = fakeEngineClient({ registerDevice: () => Promise.reject(refusal) });
    const coreKit = fakeCoreKitSession({ loggedIn: true });

    await expect(registerThisDevice(coreKit.session, engine.client.facade)).rejects.toBe(refusal);
    expect(coreKit.session.identityToken()).toBeNull();
  });

  it('keeps the token over a refusal that did not spend it', async () => {
    const engine = fakeEngineClient({
      registerDevice: () => Promise.reject(new EngineRequestError('offline', 'seam')),
    });
    const coreKit = fakeCoreKitSession({ loggedIn: true });

    await expect(registerThisDevice(coreKit.session, engine.client.facade)).rejects.toThrow();
    expect(coreKit.session.identityToken()).toBe(FAKE_IDENTITY_TOKEN);
  });
});
