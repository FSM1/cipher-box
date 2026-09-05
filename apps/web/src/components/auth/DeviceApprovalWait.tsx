import { useCallback, useEffect, useRef, useState } from 'react';
import type { EngineFacade } from '@cipherbox/client';
import type { WebCoreKitSession } from '../../auth/coreKit';
import { useCoreKit } from '../../auth/CoreKitProvider';
import { openApprovalSession, type ApprovalSession } from '../../auth/deviceApprovalApi';
import { useAuth } from '../../auth/useAuth';
import { apiBaseUrl } from '../../engine/config';
import { useCountdown } from '../../hooks/useCountdown';
import { useOnlineStatus } from '../../hooks/useOnlineStatus';
import { useVisibility } from '../../hooks/useVisibility';
import { useEngine } from '../../providers/EngineProvider';
import { erase } from '../../lib/erase';
import { errorMessage } from '../../lib/errorMessage';
import { LoginError } from '@cipherbox/auth-ui';

/** Short: the member is watching this screen, and the rendezvous is short-lived. */
const POLL_MS = 3000;

const NO_TOKEN = 'sign in again on this browser before you ask another device to approve it';

const NO_IDENTITY = 'this browser holds no device identity key — use your recovery phrase';

const UNEXPECTED = 'the engine answered this rendezvous with a step this build does not know';

const DENIED = 'the other device turned this sign-in down';

const GONE = 'this request expired before another device answered it';

/** Where the wait stands. Each end state is its own message, never a retry. */
type Stage = 'opening' | 'waiting' | 'adopting' | 'denied' | 'gone';

/** What the member compares by eye, and how long they have to do it. */
interface Rendezvous {
  requestId: string;
  devicePublicKey: string;
  comparisonValue: string;
  expiresAt: string;
  /**
   * The session that opened this row, carried with it: an exit that clears the
   * shared handle must still be able to drop the row it is abandoning.
   */
  session: ApprovalSession;
}

export interface DeviceApprovalWaitProps {
  /** Back to the recovery phrase, which is every account's guaranteed path. */
  onUseRecoveryPhrase: () => void;
  /** Back to the chooser, once this rendezvous is abandoned. */
  onCancel: () => void;
}

/**
 * The requester's half of a device approval (ADR 0009 D1): this browser opens a
 * rendezvous and waits for a device the member already uses to answer it.
 *
 * The comparison value is the whole defence. The relay never sees the factor and
 * never inspects the exchange, so what stops a relayed request from being
 * approved is a member reading the same digits on both screens.
 *
 * The recovery phrase stays one click away throughout: it is the path that works
 * when no other device does (ADR 0009 D2).
 */
export function DeviceApprovalWait({ onUseRecoveryPhrase, onCancel }: DeviceApprovalWaitProps) {
  const client = useEngine();
  const { session } = useCoreKit();
  const { completeDeviceApproval } = useAuth();
  const online = useOnlineStatus();
  const visible = useVisibility();
  const [stage, setStage] = useState<Stage>('opening');
  const [rendezvous, setRendezvous] = useState<Rendezvous | null>(null);
  const [error, setError] = useState<string | null>(null);
  const countdown = useCountdown(rendezvous?.expiresAt ?? null);

  // The scalar is this browser's half of the seal and it is ours to erase. The
  // relay session holds a scoped token that reaches no storage and dies with
  // the tab.
  const scalar = useRef<Uint8Array | null>(null);
  const relay = useRef<ApprovalSession | null>(null);
  const wipe = useCallback(() => {
    erase(scalar.current);
    scalar.current = null;
  }, []);

  // Cleared at the top of the effect body, so React's development double-invoke
  // — cleanup then the same effect again on the same instance — leaves the
  // screen live rather than stranded at "opening".
  const disposed = useRef(false);
  useEffect(() => {
    disposed.current = false;
    return () => {
      disposed.current = true;
    };
  }, []);

  // The scalar is erased however the screen goes away, not only by its own two
  // buttons: a route change elsewhere would otherwise strand it.
  useEffect(() => wipe, [wipe]);

  // One rendezvous per mount: a second open would strand the first as a row the
  // member is never shown but an approver can still be asked to answer.
  const opening = useRef(false);

  /** Whether an answer has already been taken, so only one poll acts on it. */
  const settling = useRef(false);

  useEffect(() => {
    if (client === null || session === null || opening.current) return;
    opening.current = true;
    void open(client.facade, session).then(
      (opened) => {
        // The screen can go away while the open is still in flight. The row it
        // just created would then stay answerable, so drop it here rather than
        // commit state nobody will read.
        if (disposed.current) {
          wipe();
          void opened.session.abandon(opened.requestId);
          return;
        }
        setRendezvous(opened);
        setStage('waiting');
      },
      (failure: unknown) => {
        wipe();
        if (!disposed.current) setError(errorMessage(failure));
      }
    );

    async function open(facade: EngineFacade, active: WebCoreKitSession): Promise<Rendezvous> {
      const identity = active.deviceIdentity();
      if (identity === null) throw new Error(NO_IDENTITY);
      const identityToken = active.identityToken();
      if (identityToken === null) throw new Error(NO_TOKEN);
      const opened = await openApprovalSession(apiBaseUrl(import.meta.env), identityToken);
      relay.current = opened;
      const cut = crypto.getRandomValues(new Uint8Array(32));
      scalar.current = cut;
      const devicePublicKey = await identity.publicKeyHex();
      const started = await facade.deviceRendezvous({ kind: 'open', devicePublicKey, scalar: cut });
      if (started.kind !== 'opened') throw new Error(UNEXPECTED);
      const signature = await identity.sign(Uint8Array.from(started.requestPayload));
      const { requestId, expiresAt } = await opened.open(
        devicePublicKey,
        started.ephemeralPublicKey,
        signature
      );
      // The value covers only what this device fixed before it spoke to the
      // relay, so it is known before the rendezvous has an id.
      return {
        requestId,
        devicePublicKey,
        comparisonValue: started.comparisonValue,
        expiresAt,
        session: opened,
      };
    }
  }, [client, session]);

  // A backgrounded or offline tab has nothing to poll for, and the row expires
  // on its own either way.
  useEffect(() => {
    if (stage !== 'waiting' || rendezvous === null || client === null || !online || !visible)
      return;
    const facade = client.facade;

    const poll = async (): Promise<void> => {
      const state = await relay.current?.poll(rendezvous.requestId);
      if (disposed.current || state === undefined || state.status === 'pending') return;
      // A settled rendezvous is served once and its row is then gone, so a poll
      // that overlaps this one would report the row as expired while this one
      // is still opening its factor.
      if (settling.current) return;
      settling.current = true;
      if (state.status !== 'approved') {
        wipe();
        setStage(state.status === 'denied' ? 'denied' : 'gone');
        return;
      }
      setStage('adopting');
      const cut = scalar.current;
      // Fail closed: opening the seal with anything but the scalar this
      // rendezvous was cut with would hand the engine a factor from nowhere.
      if (cut === null) throw new Error('this request no longer holds its half of the seal');
      const opened = await facade.deviceRendezvous({
        kind: 'openFactor',
        sealedFactor: state.sealedFactor,
        requestId: rendezvous.requestId,
        requesterDevicePublicKey: rendezvous.devicePublicKey,
        responderDevicePublicKey: state.responderDevicePublicKey,
        responseSignature: state.responseSignature,
        scalar: cut,
      });
      wipe();
      if (opened.kind !== 'factor') throw new Error(UNEXPECTED);
      try {
        await completeDeviceApproval(opened.factorKey);
      } finally {
        erase(opened.factorKey);
      }
    };

    const run = () =>
      void poll().catch((failure: unknown) => {
        if (!disposed.current) setError(errorMessage(failure));
      });
    run();
    const tick = setInterval(run, POLL_MS);
    return () => clearInterval(tick);
  }, [client, completeDeviceApproval, online, rendezvous, stage, visible, wipe]);

  /**
   * Leaves the screen by either exit. Both erase the scalar and drop the row:
   * a row left open is one an approver is still asked to answer for a sign-in
   * this member has walked away from.
   */
  const leave = (then: () => void) => {
    const open = rendezvous;
    wipe();
    // The row's own session, not the shared handle: clearing the handle must
    // not strand a row this exit is meant to drop.
    if (open !== null) void open.session.abandon(open.requestId);
    relay.current = null;
    then();
  };

  return (
    <div className="recovery-panel" data-testid="device-approval-wait">
      <h2>approve from another device</h2>
      <p className="login-description">
        open CipherBox on a device you already use. it will ask you to approve this sign-in. check
        that it shows the value below.
      </p>

      {/* Announced, not only shown: the member reads these digits against a
          second screen, so a reader that never speaks them hides the one check
          the flow rests on. */}
      {rendezvous !== null && (
        <p className="approval-value" aria-live="polite" data-testid="approval-comparison-value">
          {rendezvous.comparisonValue}
        </p>
      )}

      <p className="login-description" aria-live="polite" data-testid="device-approval-stage">
        {stage === 'opening' && 'opening a request...'}
        {stage === 'waiting' &&
          (countdown === null ? 'waiting for the other device...' : `waiting — ${countdown} left`)}
        {stage === 'adopting' && 'approved — opening your vault...'}
        {stage === 'denied' && DENIED}
        {stage === 'gone' && GONE}
      </p>

      <div className="recovery-actions">
        <button
          type="button"
          className="terminal-btn terminal-btn--filled"
          onClick={() => leave(onUseRecoveryPhrase)}
          data-testid="device-approval-use-phrase"
        >
          use your recovery phrase
        </button>
        <button
          type="button"
          className="email-login-restart"
          onClick={() => leave(onCancel)}
          data-testid="device-approval-cancel"
        >
          cancel
        </button>
      </div>

      {error !== null && <LoginError message={error} />}
    </div>
  );
}
