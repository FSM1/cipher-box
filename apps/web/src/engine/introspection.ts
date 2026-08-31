/**
 * The e2e seam (blueprint/testing.md "E2E"): read-only taps over the facade's
 * snapshot and event stream, the cold start the suite drives in place of an
 * interactive Core Kit login, and the device-approval steps a second session
 * drives in place of one.
 *
 * Gated on `VITE_E2E_HOOK` rather than on `DEV`, because the suite runs against
 * the production static build — the artifact a `DEV` gate would exclude the
 * hook from is the very one under test.
 */

import { fromHex, toHex } from '@cipherbox/client';
import { handOffLoginSecret } from '@cipherbox/login';
import type { SecretRearm } from '@cipherbox/login';
import type {
  EngineClient,
  EngineFacade,
  EventDescriptor,
  PendingApprovalDescriptor,
  SnapshotDescriptor,
} from '@cipherbox/client';
import { webDeviceIdentities } from '../auth/deviceIdentity';
import { erase } from '../lib/erase';

/**
 * A structured-clone-safe projection of an engine descriptor: `Uint8Array`
 * becomes hex and `bigint` becomes a decimal string, neither of which survives
 * the Playwright evaluation boundary as itself.
 */
export type Plain<T> = T extends Uint8Array
  ? string
  : T extends bigint
    ? string
    : T extends readonly (infer U)[]
      ? Plain<U>[]
      : T extends object
        ? { [K in keyof T]: Plain<T[K]> }
        : T;

export interface IntrospectedView {
  view: Plain<SnapshotDescriptor>;
  /** The view is the latest version and the queue holds nothing for it. */
  settled: boolean;
}

export interface EngineIntrospection {
  /** Cold-starts the engine from a 32-byte hex login secret. */
  signIn(loginSecretHex: string, accountId: string): Promise<void>;
  /** The engine's view of the vault root. */
  snapshot(): Promise<IntrospectedView>;
  /** One node's plaintext as the engine reads it back, hex like every other tap. */
  download(nodeHex: string): Promise<string>;
  /** Every engine event this tab has seen, in emission order. */
  events(): Plain<EventDescriptor>[];
  /**
   * How many times this tab has re-exported its login secret for a promotion.
   * Counted for the tab, not the client, so a rebuilt one cannot reset it.
   */
  reExports(): number;
  /** This tab's half of a device-approval rendezvous (ADR 0009). */
  approval: ApprovalTaps;
}

/** What the requester's screen holds once its rendezvous is cut. */
export interface CutRendezvous {
  devicePublicKey: string;
  ephemeralPublicKey: string;
  /** This device's signature over the pair, which the relay route verifies. */
  signature: string;
  /** The digits the member compares against the approver's screen (D3). */
  comparisonValue: string;
}

/**
 * The device-approval taps: this tab drives the same facade steps and the same
 * device identity key the two approval screens drive.
 *
 * Every secret the rendezvous cuts — the requester's scalar, the approver's seal
 * scalar, the factor itself — stays behind this seam and is erased here. A tap
 * answers with the public transcript and, for a factor, a digest of it, so no
 * assertion and no uploaded trace carries key material.
 */
export interface ApprovalTaps {
  /**
   * Registers this browser's identity key for one subject on the signed-in
   * account, as the devices pane does. The key is minted on first use (D4).
   */
  register(subject: string, identityToken: string): Promise<void>;
  /** Cuts a rendezvous the relay can carry, and keeps its scalar here. */
  open(subject: string): Promise<CutRendezvous>;
  /** The rows this signed-in account is asked to approve. */
  pending(): Promise<PendingApprovalDescriptor[]>;
  /**
   * Answers one row as the approval prompt does, and reports the digest of the
   * factor an approval minted; a denial mints none and reports `null`.
   */
  answer(
    subject: string,
    row: PendingApprovalDescriptor,
    decision: 'approve' | 'deny'
  ): Promise<string | null>;
  /**
   * Opens a factor an approver sealed back to a rendezvous this tab cut, and
   * reports its digest. Rejects when the seal does not open, which is what a
   * substituted ephemeral key leaves the honest requester holding.
   */
  adopt(sealedFactor: string, requestId: string, ephemeralPublicKey: string): Promise<string>;
  /** Erases the scalar of a rendezvous that ended without a factor. */
  forget(ephemeralPublicKey: string): void;
}

/** Survives the client rebuild a session end drives, which is the point. */
let reExports = 0;

declare global {
  interface Window {
    __CIPHERBOX_ENGINE__?: EngineIntrospection;
  }
}

/**
 * Publishes the taps for `client` on `window`, and returns it so a host can
 * wrap its client factory. A no-op outside an e2e build.
 */
export function installIntrospection(client: EngineClient, secrets?: SecretRearm): EngineClient {
  if (import.meta.env.VITE_E2E_HOOK !== 'true') return client;

  const seen: Plain<EventDescriptor>[] = [];
  client.facade.subscribe((event) => {
    seen.push(plain(event) as Plain<EventDescriptor>);
  });

  window.__CIPHERBOX_ENGINE__ = {
    signIn(loginSecretHex, accountId) {
      const source = { accountId: () => accountId };
      // Armed as the real flow arms it (`createLoginFlow`), so a promotion in
      // this tab re-exports rather than failing for want of a source the suite
      // never installed. Two exporters over the one secret: only a promotion's
      // export counts, so the cold start below leaves the tally alone.
      secrets?.use({
        ...source,
        _UNSAFE_exportTssKey: () => {
          reExports += 1;
          return Promise.resolve(loginSecretHex);
        },
      });
      return handOffLoginSecret(client.facade, {
        ...source,
        _UNSAFE_exportTssKey: () => Promise.resolve(loginSecretHex),
      });
    },
    async snapshot() {
      const view = await client.facade.snapshot(null);
      return { view: plain(view) as Plain<SnapshotDescriptor>, settled: settled(view) };
    },
    async download(nodeHex) {
      return toHex(new Uint8Array(await client.facade.download(fromHex(nodeHex))));
    },
    events: () => seen,
    reExports: () => reExports,
    approval: approvalTaps(client.facade),
  };
  return client;
}

/** A rendezvous this tab cut, keyed by the ephemeral key the relay carries. */
interface HeldCut {
  scalar: Uint8Array;
  devicePublicKey: string;
}

function approvalTaps(facade: EngineFacade): ApprovalTaps {
  const identityOf = (subject: string) => webDeviceIdentities().forSubject(subject);
  const cuts = new Map<string, HeldCut>();

  return {
    async register(subject, identityToken) {
      const identity = identityOf(subject);
      const publicKey = await identity.publicKeyHex();
      const challenge = await facade.deviceRegistrationChallenge(publicKey);
      const signature = await identity.sign(Uint8Array.from(challenge));
      await facade.registerDevice(publicKey, signature, identityToken, null);
    },

    async open(subject) {
      const identity = identityOf(subject);
      const devicePublicKey = await identity.publicKeyHex();
      const scalar = crypto.getRandomValues(new Uint8Array(32));
      let cut;
      try {
        cut = await facade.deviceRendezvous({ kind: 'open', devicePublicKey, scalar });
        if (cut.kind !== 'opened') throw new Error('the engine did not open a rendezvous');
      } catch (failure) {
        erase(scalar);
        throw failure;
      }
      cuts.set(cut.ephemeralPublicKey, { scalar, devicePublicKey });
      return {
        devicePublicKey,
        ephemeralPublicKey: cut.ephemeralPublicKey,
        signature: await identity.sign(Uint8Array.from(cut.requestPayload)),
        comparisonValue: cut.comparisonValue,
      };
    },

    pending: () => facade.pendingApprovals(),

    async answer(subject, row, decision) {
      const identity = identityOf(subject);
      const devicePublicKey = await identity.publicKeyHex();
      // A fresh factor per approval; the approver's own is never transferred
      // (ADR 0009 D5).
      const factorKey = decision === 'approve' ? crypto.getRandomValues(new Uint8Array(32)) : null;
      // Named before the step, because the step transfers these bytes to the
      // worker and leaves this realm holding a detached buffer.
      const minted = factorKey === null ? null : await digest(factorKey);
      const sealScalar = crypto.getRandomValues(new Uint8Array(32));
      let answered;
      try {
        answered = await facade.deviceRendezvous(
          factorKey === null
            ? {
                kind: 'deny',
                devicePublicKey,
                requestId: row.requestId,
                ephemeralPublicKey: row.ephemeralPublicKey,
              }
            : {
                kind: 'approve',
                devicePublicKey,
                requestId: row.requestId,
                requesterDevicePublicKey: row.requesterDevicePublicKey,
                ephemeralPublicKey: row.ephemeralPublicKey,
                sealScalar,
                factorKey,
              }
        );
      } finally {
        erase(sealScalar);
        if (factorKey !== null) erase(factorKey);
      }
      if (answered.kind !== 'response') throw new Error('the engine did not answer the rendezvous');
      const signature = await identity.sign(Uint8Array.from(answered.payload));
      await facade.respondToApproval(
        row.requestId,
        decision,
        devicePublicKey,
        row.ephemeralPublicKey,
        signature,
        answered.sealedFactor
      );
      return minted;
    },

    async adopt(sealedFactor, requestId, ephemeralPublicKey) {
      const cut = cuts.get(ephemeralPublicKey);
      if (cut === undefined) throw new Error('this tab cut no rendezvous at that key');
      let opened;
      try {
        opened = await facade.deviceRendezvous({
          kind: 'openFactor',
          sealedFactor,
          requestId,
          requesterDevicePublicKey: cut.devicePublicKey,
          scalar: cut.scalar,
        });
      } finally {
        erase(cut.scalar);
        cuts.delete(ephemeralPublicKey);
      }
      if (opened.kind !== 'factor') throw new Error('the engine did not open a factor');
      const factorKey = opened.factorKey as Uint8Array<ArrayBuffer>;
      try {
        return await digest(factorKey);
      } finally {
        factorKey.fill(0);
      }
    },

    forget(ephemeralPublicKey) {
      const cut = cuts.get(ephemeralPublicKey);
      if (cut !== undefined) erase(cut.scalar);
      cuts.delete(ephemeralPublicKey);
    },
  };
}

/** Names a secret without carrying it, so an assertion holds no key material. */
async function digest(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

/** The deterministic wait the suite polls in place of a sleep. */
function settled(view: SnapshotDescriptor): boolean {
  return (
    view.staleness === 'fresh' &&
    view.blocked === null &&
    view.children.every((child) => child.pending === 'none')
  );
}

function plain(value: unknown): unknown {
  if (value instanceof Uint8Array) return toHex(value);
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(plain);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, plain(item)]));
  }
  return value;
}
