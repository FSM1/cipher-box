/**
 * The device identity keys registered to this account (ADR 0009 D4), and the two
 * exchanges that change the list. Each change re-reads, so the pane shows what
 * the account now carries.
 */

import { useCallback, useEffect, useState } from 'react';
import type { EngineFacade, RegisteredDeviceDescriptor } from '@cipherbox/client';
import { useCoreKit } from '../auth/CoreKitProvider';
import {
  isAuthRefusal,
  NO_IDENTITY,
  NO_TOKEN,
  registerThisDevice,
  SIGN_IN_TO_SAVE,
} from '../auth/registerThisDevice';
import { errorMessage } from '../lib/errorMessage';
import { useCommandRunner } from './useCommandRunner';

const REFUSED = `this sign-in can no longer register a device. ${SIGN_IN_TO_SAVE}`;

/**
 * Whether a registration can run now. `reading` holds the control shut while
 * this browser's key is read; `closed` names a cause the member can act on.
 */
export type Registration =
  | { state: 'open' }
  | { state: 'reading' }
  | { state: 'closed'; reason: string };

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

  const read = useCallback(async (facade: EngineFacade) => {
    const listed = await facade.devices();
    setDevices(listed);
    return listed;
  }, []);

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
      // The failure is the closed reason; the list still renders.
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
        if (!session) throw new Error('no session');
        try {
          setThisDevice(await registerThisDevice(session, facade));
        } catch (refusal) {
          if (!isAuthRefusal(refusal)) throw refusal;
          // A spent token can mean the key already landed: the sign-in did it,
          // or the response to an earlier try was lost.
          const listed = await read(facade);
          if (thisDevice !== null && listed.some((row) => row.publicKey === thisDevice)) return;
          // The closed reason names the cause, so no error line repeats it.
          setRefused(true);
          return;
        }
        await read(facade);
      }),
    [run, read, session, thisDevice]
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
    if (thisDevice === null) return { state: 'reading' };
    if (refused) return { state: 'closed', reason: REFUSED };
    if (session.identityToken() === null) return { state: 'closed', reason: NO_TOKEN };
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
