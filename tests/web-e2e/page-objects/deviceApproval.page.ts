import type { Browser, Page } from '@playwright/test';
import type { PendingApprovalDescriptor } from '@cipherbox/client';
import { openApprovalSession, type ApprovalSession } from '@web/auth/deviceApprovalApi';
import type { CutRendezvous } from '@web/engine/introspection';
import { apiBaseUrl } from '../identity';
import { VaultPage } from './vault.page';

/**
 * One device in a two-session approval: its own browser context, its own
 * identity key, and the engine that runs its half of the rendezvous.
 *
 * Every step goes through the tab's engine, so the comparison value, the seal
 * and the factor are the shipped implementation's, not the suite's.
 */
export class ApprovalDevice {
  constructor(
    readonly page: Page,
    /** The identity subject this browser holds a key for. */
    readonly subject: string
  ) {}

  register(identityToken: string): Promise<void> {
    return this.page.evaluate(
      ({ subject, token }) => window.__CIPHERBOX_ENGINE__!.approval.register(subject, token),
      { subject: this.subject, token: identityToken }
    );
  }

  cut(): Promise<CutRendezvous> {
    return this.page.evaluate(
      (subject) => window.__CIPHERBOX_ENGINE__!.approval.open(subject),
      this.subject
    );
  }

  pending(): Promise<PendingApprovalDescriptor[]> {
    return this.page.evaluate(() => window.__CIPHERBOX_ENGINE__!.approval.pending());
  }

  answer(row: PendingApprovalDescriptor, decision: 'approve' | 'deny'): Promise<string | null> {
    return this.page.evaluate(
      ({ subject, held, choice }) =>
        window.__CIPHERBOX_ENGINE__!.approval.answer(subject, held, choice),
      { subject: this.subject, held: row, choice: decision }
    );
  }

  adopt(
    sealedFactor: string,
    requestId: string,
    ephemeralPublicKey: string,
    responderDevicePublicKey: string,
    responseSignature: string
  ): Promise<string> {
    return this.page.evaluate(
      ({ sealed, id, ephemeral, responder, signature }) =>
        window.__CIPHERBOX_ENGINE__!.approval.adopt(sealed, id, ephemeral, responder, signature),
      {
        sealed: sealedFactor,
        id: requestId,
        ephemeral: ephemeralPublicKey,
        responder: responderDevicePublicKey,
        signature: responseSignature,
      }
    );
  }

  forget(ephemeralPublicKey: string): Promise<void> {
    return this.page.evaluate(
      (ephemeral) => window.__CIPHERBOX_ENGINE__!.approval.forget(ephemeral),
      ephemeralPublicKey
    );
  }

  close(): Promise<void> {
    return this.page.context().close();
  }
}

/**
 * A device in its own browser context. `signIn` cold-starts a vault, which the
 * approver needs and the requester — a device that cannot yet reconstruct —
 * deliberately does not.
 */
export async function openDevice(
  browser: Browser,
  subject: string,
  signIn = false
): Promise<ApprovalDevice> {
  const page = await (await browser.newContext()).newPage();
  const vault = new VaultPage(page);
  await vault.open();
  if (signIn) await vault.coldStart();
  return new ApprovalDevice(page, subject);
}

/**
 * The bulletin board between the two devices, driven from the suite rather than
 * from the requester's tab: the relay is the party ADR 0009 does not trust, and
 * a spec has to be able to carry something other than what the requester cut.
 * The client is the shipped one, so the specs cover it too.
 */
export function openRelay(identityToken: string): Promise<ApprovalSession> {
  return openApprovalSession(apiBaseUrl(), identityToken);
}

/** Carries one cut rendezvous to the account, field for field. */
export function carry(relay: ApprovalSession, cut: CutRendezvous) {
  return relay.open(cut.devicePublicKey, cut.ephemeralPublicKey, cut.signature);
}
