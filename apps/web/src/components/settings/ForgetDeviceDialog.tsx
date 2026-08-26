import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../auth/useAuth';
import { Modal } from '../ui/Modal';

/**
 * Forget this device: the erase a logout deliberately does not do — the engine's
 * durable seams, this device's Core Kit store and wrapping key, and a
 * best-effort drop of its factor (blueprint/web-client.md "Logout").
 *
 * Device-scoped and irreversible for this browser, so it asks first. The vault
 * itself is untouched: what is erased is what this device kept of it.
 */
export function ForgetDeviceDialog({ onClose }: { onClose: () => void }) {
  const { forgetDevice, isBusy, error } = useAuth();
  const [confirmed, setConfirmed] = useState(false);
  const navigate = useNavigate();

  const forget = async () => {
    try {
      await forgetDevice();
    } catch {
      // `useAuth` already surfaces the refusal as `error`, which `Modal` renders.
      return;
    }
    navigate('/');
  };

  return (
    <Modal onClose={onClose} title="forget this device" error={error} busy={isBusy}>
      <div className="dialog-content" data-testid="forget-device-dialog">
        <p className="dialog-message">
          erase everything this browser holds of your vault — cached blocks, queued uploads, staged
          bytes, and this device&apos;s sign-in.
        </p>
        <p className="dialog-message">
          your vault and its contents are not touched. you can sign in again here from any login
          method the account still has.
        </p>
        <label className="settings-confirm" htmlFor="forget-device-ack">
          <input
            id="forget-device-ack"
            type="checkbox"
            checked={confirmed}
            onChange={(event) => setConfirmed(event.target.checked)}
          />
          <span>i understand this browser will be signed out and cleared</span>
        </label>
        <div className="dialog-actions">
          <button type="button" className="dialog-button" onClick={onClose} disabled={isBusy}>
            cancel
          </button>
          <button
            type="button"
            className="dialog-button dialog-button--danger"
            onClick={() => void forget()}
            disabled={isBusy || !confirmed}
            data-testid="forget-device-confirm"
          >
            {isBusy ? 'forgetting...' : 'forget this device'}
          </button>
        </div>
      </div>
    </Modal>
  );
}
