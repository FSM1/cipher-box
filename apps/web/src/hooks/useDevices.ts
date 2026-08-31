/**
 * The device identity keys registered to this account (ADR 0009 D4), and the two
 * exchanges that change the list. Each change re-reads, so the pane shows what
 * the account now carries.
 */

import { useCallback, useEffect, useState } from 'react';
import type { EngineFacade, RegisteredDeviceDescriptor } from '@cipherbox/client';
import { useCoreKit } from '../auth/CoreKitProvider';
import { useCommandRunner } from './useCommandRunner';

/** A registration signs an identity token, which only a fresh sign-in carries. */
const NO_TOKEN = 'sign in again on this browser before you register it';

const NO_IDENTITY = 'this browser holds no device identity key';

export interface DevicesRead {
  devices: RegisteredDeviceDescriptor[];
  /** This browser's own key for the signed-in member; `null` where it has none. */
  thisDevice: string | null;
  busy: boolean;
  error: string | null;
  /**
   * Whether a registration can run now. It signs the identity token of this
   * sign-in, which a session restored across a reload no longer carries.
   */
  canRegister: boolean;
  /** Registers this browser's key, so it can approve a sign-in elsewhere. */
  register(): void;
  revoke(deviceId: string): void;
}

export function useDevices(): DevicesRead {
  const { session } = useCoreKit();
  const [devices, setDevices] = useState<RegisteredDeviceDescriptor[]>([]);
  const [thisDevice, setThisDevice] = useState<string | null>(null);
  const { busy, error, run } = useCommandRunner<'devices' | 'registerDevice' | 'revokeDevice'>();

  const read = useCallback(async (facade: EngineFacade) => setDevices(await facade.devices()), []);

  const reload = useCallback(() => run('devices', read), [run, read]);

  useEffect(() => {
    void reload();
  }, [reload]);

  useEffect(() => {
    const identity = session?.deviceIdentity();
    // A session holding no key must not keep the last one's answer: the pane
    // would go on marking a row as this device and offer no way to register.
    if (!identity) {
      setThisDevice(null);
      return;
    }
    let live = true;
    void identity.publicKeyHex().then(
      (publicKey) => {
        if (live) setThisDevice(publicKey);
      },
      // A browser that can hold no key still lists the account's other devices.
      () => undefined
    );
    return () => {
      live = false;
    };
  }, [session]);

  const register = useCallback(
    () =>
      void run('registerDevice', async (facade) => {
        const identity = session?.deviceIdentity();
        if (!identity) throw new Error(NO_IDENTITY);
        const identityToken = session?.identityToken() ?? null;
        if (identityToken === null) throw new Error(NO_TOKEN);
        const publicKey = await identity.publicKeyHex();
        const challenge = await facade.deviceRegistrationChallenge(publicKey);
        const signature = await identity.sign(Uint8Array.from(challenge));
        await facade.registerDevice(publicKey, signature, identityToken, null);
        setThisDevice(publicKey);
        await read(facade);
      }),
    [run, read, session]
  );

  const revoke = useCallback(
    (deviceId: string) =>
      void run('revokeDevice', async (facade) => {
        await facade.revokeDevice(deviceId);
        await read(facade);
      }),
    [run, read]
  );

  return {
    devices,
    thisDevice,
    canRegister: thisDevice !== null && (session?.identityToken() ?? null) !== null,
    busy: busy !== null,
    error,
    register,
    revoke,
  };
}
