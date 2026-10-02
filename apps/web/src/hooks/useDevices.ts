/**
 * The device identity keys registered to this account (ADR 0009 D4), and the two
 * exchanges that change the list. Each change re-reads, so the pane shows what
 * the account now carries.
 */

import { useCallback, useEffect, useState } from 'react';
import {
  EngineRequestError,
  type EngineFacade,
  type RegisteredDeviceDescriptor,
} from '@cipherbox/client';
import { useCoreKit } from '../auth/CoreKitProvider';
import {
  AUTH_REFUSAL,
  NO_IDENTITY,
  NO_TOKEN,
  registerThisDevice,
} from '../auth/registerThisDevice';
import { errorMessage } from '../lib/errorMessage';
import { useCommandRunner } from './useCommandRunner';

const READING = 'reading the device key of this browser';

const REFUSED =
  'this sign-in can no longer register a device. sign in again with "save this device" checked';

/** Whether a registration can run now, and if not, the cause a member can act on. */
export type Registration = { state: 'open' } | { state: 'closed'; reason: string };

export interface DevicesRead {
  devices: RegisteredDeviceDescriptor[];
  /** This browser's own key for the signed-in member; `null` where it has none. */
  thisDevice: string | null;
  busy: boolean;
  error: string | null;
  registration: Registration;
  /** Registers this browser's key, so it can approve a sign-in elsewhere. */
  register(): void;
  revoke(deviceId: string): void;
}

export function useDevices(): DevicesRead {
  const { session } = useCoreKit();
  const [devices, setDevices] = useState<RegisteredDeviceDescriptor[]>([]);
  const [thisDevice, setThisDevice] = useState<string | null>(null);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [refused, setRefused] = useState(false);
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
    setThisDevice(null);
    setKeyError(null);
    if (!identity) return;
    let live = true;
    void identity.publicKeyHex().then(
      (publicKey) => {
        if (live) setThisDevice(publicKey);
      },
      // A browser that can hold no key still lists the account's other devices.
      (failure: unknown) => {
        if (live) setKeyError(errorMessage(failure));
      }
    );
    return () => {
      live = false;
    };
  }, [session]);

  const register = useCallback(
    () =>
      void run('registerDevice', async (facade) => {
        if (!session) throw new Error(NO_IDENTITY);
        try {
          setThisDevice(await registerThisDevice(session, facade));
        } catch (refusal) {
          if (refusal instanceof EngineRequestError && refusal.code === AUTH_REFUSAL) {
            setRefused(true);
          }
          throw refusal;
        }
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

  const registration = ((): Registration => {
    if (keyError !== null) return { state: 'closed', reason: keyError };
    if (!session?.deviceIdentity()) return { state: 'closed', reason: NO_IDENTITY };
    if (refused) return { state: 'closed', reason: REFUSED };
    if (session.identityToken() === null) return { state: 'closed', reason: NO_TOKEN };
    if (thisDevice === null) return { state: 'closed', reason: READING };
    return { state: 'open' };
  })();

  return {
    devices,
    thisDevice,
    registration,
    busy: busy !== null,
    error,
    register,
    revoke,
  };
}
