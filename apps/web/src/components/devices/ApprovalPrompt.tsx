import { useCallback, useEffect, useRef, useState } from 'react';
import type { DeviceRendezvousStep, PendingApprovalDescriptor } from '@cipherbox/client';
import { useCoreKit } from '../../auth/CoreKitProvider';
import { useCommandRunner } from '../../hooks/useCommandRunner';
import { erase } from '../../lib/erase';
import { useCountdown } from '../../hooks/useCountdown';
import { useOnlineStatus } from '../../hooks/useOnlineStatus';
import { useVisibility } from '../../hooks/useVisibility';
import { useEngine } from '../../providers/EngineProvider';
import { useAuthState } from '../../stores/auth.store';
import { Modal } from '../ui/Modal';

/** Short enough that a member reaches the prompt while the rendezvous is live. */
const POLL_MS = 5000;

const NO_IDENTITY = 'this browser holds no device identity key, so it cannot approve a sign-in';

const UNEXPECTED = 'the engine answered this rendezvous with a step this build does not know';

/** A dispatch that is answering a rendezvous, so the modal reports its outcome. */
type Answering = 'approve' | 'deny';

/**
 * The approver's half of a device approval (ADR 0009 D1). The engine serves only
 * rows whose request signature verified, so what is left for the member is the
 * one check no signature can make: that the digits on this screen are the digits
 * on the screen asking to be let in.
 *
 * Mounted in the signed-in frame, because a request arrives while the member is
 * doing something else.
 */
export function ApprovalPrompt() {
  const client = useEngine();
  const { session } = useCoreKit();
  const { factorPolicy } = useAuthState();
  const online = useOnlineStatus();
  const visible = useVisibility();
  const [pending, setPending] = useState<PendingApprovalDescriptor[]>([]);
  // Rows this tab answered or set aside. A poll keeps serving a row until it is
  // collected, so without this the prompt returns every few seconds.
  const [retired, setRetired] = useState<readonly string[]>([]);
  // Which request the member confirmed a match for. A new request is a new
  // comparison, so its confirmation is its own rather than an inherited flag.
  const [matchedFor, setMatchedFor] = useState<string | null>(null);
  const { busy, error, run, clearError } = useCommandRunner<Answering>();

  // Cleared on every exit from the seal, including the refused one and the
  // unmount. `erase` states why a transferred buffer is left alone.
  const factorKey = useRef<Uint8Array | null>(null);
  const sealScalar = useRef<Uint8Array | null>(null);
  const wipe = useCallback(() => {
    erase(factorKey.current);
    factorKey.current = null;
    erase(sealScalar.current);
    sealScalar.current = null;
  }, []);
  useEffect(() => wipe, [wipe]);

  // A rendezvous expires, so a backgrounded or offline tab has nothing to poll
  // for; an account with no factor policy can hold no approvable request.
  const polling = client !== null && factorPolicy && online && visible;

  useEffect(() => {
    if (!polling) return;
    let live = true;
    const facade = client.facade;
    // The pending list is account-scoped, so the policy alone would have every
    // signed-in browser raise prompts the API then refuses. Only a device the
    // registry carries may answer one, and a revocation elsewhere leaves this
    // session signed in.
    let mine: string | null = null;
    const carriesThisDevice = async (): Promise<boolean> => {
      mine ??= (await session?.deviceIdentity()?.publicKeyHex()) ?? null;
      if (mine === null) return false;
      return (await facade.devices()).some((row) => row.publicKey === mine);
    };
    // Read until it holds, so a registration made in this session needs no
    // reload, and again whenever a row would be raised.
    let registered = false;
    const poll = async (): Promise<void> => {
      if (!registered) {
        registered = await carriesThisDevice();
        if (!registered) return;
      }
      const rows = await facade.pendingApprovals();
      if (rows.length > 0) registered = await carriesThisDevice();
      if (live) setPending(registered ? rows : []);
    };
    // A failed poll is the ordinary offline case; the next one answers.
    const run = () => void poll().catch(() => undefined);
    run();
    const tick = setInterval(run, POLL_MS);
    return () => {
      live = false;
      clearInterval(tick);
    };
  }, [client, polling, session]);

  const request = pending.find((row) => !retired.includes(row.requestId)) ?? null;
  const requestId = request?.requestId ?? null;
  const countdown = useCountdown(request?.expiresAt ?? null);

  // Keyed by the rendezvous, never by the device that opened it: one device may
  // open two, and a confirmation carried across them would approve a comparison
  // value nobody read.
  const matched = requestId !== null && matchedFor === requestId;

  useEffect(() => clearError(), [requestId, clearError]);

  /** Retires a row this tab is done with, answered or set aside. */
  const settled = (requestId: string) =>
    setRetired((rows) => (rows.includes(requestId) ? rows : [...rows, requestId]));

  /** The step this answer runs, cutting the seal material an approval needs. */
  const step = async (
    row: PendingApprovalDescriptor,
    decision: Answering,
    devicePublicKey: string
  ): Promise<DeviceRendezvousStep> => {
    if (decision === 'deny') {
      return {
        kind: 'deny',
        devicePublicKey,
        requestId: row.requestId,
        ephemeralPublicKey: row.ephemeralPublicKey,
      };
    }
    if (!session) throw new Error(NO_IDENTITY);
    const factor = await session.mintApprovalFactor();
    factorKey.current = factor;
    const seal = crypto.getRandomValues(new Uint8Array(32));
    sealScalar.current = seal;
    return {
      kind: 'approve',
      devicePublicKey,
      requestId: row.requestId,
      requesterDevicePublicKey: row.requesterDevicePublicKey,
      ephemeralPublicKey: row.ephemeralPublicKey,
      sealScalar: seal,
      factorKey: factor,
    };
  };

  const answer = (row: PendingApprovalDescriptor, decision: Answering) =>
    void run(decision, async (facade) => {
      const identity = session?.deviceIdentity();
      if (!identity) throw new Error(NO_IDENTITY);
      const devicePublicKey = await identity.publicKeyHex();
      let sealed;
      try {
        const chosen = await step(row, decision, devicePublicKey);
        sealed = await facade.deviceRendezvous(chosen);
      } finally {
        wipe();
      }
      if (sealed.kind !== 'response') throw new Error(UNEXPECTED);
      const signature = await identity.sign(Uint8Array.from(sealed.payload));
      await facade.respondToApproval(
        row.requestId,
        decision,
        devicePublicKey,
        row.ephemeralPublicKey,
        signature,
        // A denial seals nothing here, whatever the step answered with.
        decision === 'approve' ? sealed.sealedFactor : null
      );
      settled(row.requestId);
    });

  if (request === null) return null;

  return (
    <Modal
      onClose={() => settled(request.requestId)}
      title="approve this sign-in?"
      error={error}
      busy={busy !== null}
    >
      <div className="dialog-content" data-testid="approval-prompt">
        <p className="dialog-message">
          a browser signed in to your account and asked this device to let it in. check the value
          below against the one on that browser.
        </p>
        <p className="approval-value" data-testid="approval-comparison-value">
          {request.comparisonValue}
        </p>
        {countdown !== null && (
          <p className="dialog-message" data-testid="approval-countdown">
            this request expires in {countdown}
          </p>
        )}
        <label className="recovery-ack" htmlFor="approval-match">
          <input
            id="approval-match"
            type="checkbox"
            checked={matched}
            onChange={(event) => setMatchedFor(event.target.checked ? requestId : null)}
            data-testid="approval-match"
          />
          <span>the value above is the value that browser shows</span>
        </label>
        <div className="dialog-actions">
          <button
            type="button"
            className="dialog-button dialog-button--danger"
            onClick={() => answer(request, 'deny')}
            disabled={busy !== null}
            data-testid="approval-deny"
          >
            {busy === 'deny' ? 'denying...' : 'deny'}
          </button>
          <button
            type="button"
            className="dialog-button dialog-button--primary"
            onClick={() => answer(request, 'approve')}
            disabled={busy !== null || !matched}
            data-testid="approval-approve"
          >
            {busy === 'approve' ? 'approving...' : 'approve'}
          </button>
        </div>
      </div>
    </Modal>
  );
}
