import { useState } from 'react';
import type { RegisteredDeviceDescriptor } from '@cipherbox/client';
import { useDevices } from '../../hooks/useDevices';
import { formatDate } from '../../utils/format';
import { Modal } from '../ui/Modal';

/** Enough of a key to tell two rows apart by eye, and no more. */
const KEY_PREFIX = 12;

/** The registry bounds a label, but the row is server text and is cut anyway. */
const LABEL_MAX = 64;

/** Why the register control is closed: the token it signs comes from a login. */
const NEEDS_FRESH_SIGN_IN = 'sign in again on this browser to register it';

/** What a revoke does and does not do (ADR 0009 D5). */
const REVOKE_MEANS =
  'this device can no longer approve a sign-in. it does not un-share anything the device already holds.';

/**
 * Names one row, for the revoke control and its confirmation. Every row carries
 * the same destructive control, so without the device in the name a member
 * cannot tell the rows apart by ear, and confirms a revoke that names nothing.
 */
function names(device: RegisteredDeviceDescriptor): string {
  return `${device.label?.slice(0, LABEL_MAX) ?? 'unlabelled'} (${device.publicKey.slice(0, KEY_PREFIX)})`;
}

/** A date the API served. An instant it cannot parse says so rather than
 * printing whatever the server sent. */
function on(timestamp: string): string {
  const millis = Date.parse(timestamp);
  return Number.isNaN(millis) ? 'an unknown time' : formatDate(millis);
}

/**
 * The device identity keys on this account: what may approve a sign-in on a new
 * browser, and the one exchange that takes that away.
 *
 * A label is context the registering device chose, never evidence — the
 * comparison value on the approval prompt is what an approval rests on.
 */
export function DevicesPane() {
  const { devices, thisDevice, canRegister, busy, error, register, revoke } = useDevices();
  const [revoking, setRevoking] = useState<RegisteredDeviceDescriptor | null>(null);
  const registered = thisDevice !== null && devices.some((row) => row.publicKey === thisDevice);

  const confirm = (device: RegisteredDeviceDescriptor) => {
    setRevoking(null);
    revoke(device.id);
  };

  return (
    <section className="settings-section" data-testid="settings-devices">
      <h3>authorized devices</h3>
      <p className="sharing-note">
        {'// each key here can approve a sign-in on a new browser. labels are context, not proof.'}
      </p>

      <ul className="settings-devices">
        {devices.map((device) => {
          const own = device.publicKey === thisDevice;
          return (
            <li key={device.id} className="settings-device-row" data-testid="settings-device-row">
              <span className="settings-device-label">
                {device.label?.slice(0, LABEL_MAX) ?? 'unlabelled'}
              </span>
              <span className="settings-device-key">{device.publicKey.slice(0, KEY_PREFIX)}</span>
              <span className="settings-device-when">registered {on(device.createdAt)}</span>
              <span className="settings-device-when">last seen {on(device.lastSeenAt)}</span>
              <span className="settings-device-own" data-testid="settings-device-own">
                {own ? 'this device' : ''}
              </span>
              <button
                type="button"
                className="terminal-btn terminal-btn--danger"
                onClick={() => setRevoking(device)}
                disabled={busy}
                title={REVOKE_MEANS}
                aria-label={`revoke ${names(device)} — ${REVOKE_MEANS}`}
                data-testid="settings-device-revoke"
              >
                revoke
              </button>
            </li>
          );
        })}
      </ul>

      {!registered && (
        <div className="settings-actions">
          <button
            type="button"
            className="terminal-btn"
            onClick={register}
            disabled={busy || !canRegister}
            title={canRegister ? undefined : NEEDS_FRESH_SIGN_IN}
            aria-label={canRegister ? undefined : `register this device — ${NEEDS_FRESH_SIGN_IN}`}
            data-testid="settings-device-register"
          >
            register this device
          </button>
        </div>
      )}

      {error !== null && (
        <p className="dialog-error" role="alert" data-testid="settings-devices-error">
          {error}
        </p>
      )}

      {revoking !== null && (
        <Modal onClose={() => setRevoking(null)} title="revoke this device">
          <div className="dialog-content" data-testid="settings-device-revoke-dialog">
            <p className="dialog-message" data-testid="settings-device-revoke-named">
              {names(revoking)}
            </p>
            <p className="dialog-message">{REVOKE_MEANS}</p>
            <p className="dialog-message">
              the device signs in again with any login method the account still has.
            </p>
            <div className="dialog-actions">
              <button type="button" className="dialog-button" onClick={() => setRevoking(null)}>
                cancel
              </button>
              <button
                type="button"
                className="dialog-button dialog-button--danger"
                onClick={() => confirm(revoking)}
                data-testid="settings-device-revoke-confirm"
              >
                revoke
              </button>
            </div>
          </div>
        </Modal>
      )}
    </section>
  );
}
