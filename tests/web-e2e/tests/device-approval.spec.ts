/**
 * Cross-device approval, driven as two sessions (ADR 0009 consequence 6).
 *
 * Each spec runs two engines in two browser contexts against the live API: one
 * signed in and registered as an approver, one cold — a device that cannot yet
 * reconstruct. Every rendezvous step is the shipped implementation's; the suite
 * plays only the relay.
 *
 * The Core Kit factor a real approval adopts is out of reach here
 * (blueprint/testing.md exempts interactive Core Kit login), so the approver
 * mints the fresh factor ADR 0009 D5 fixes, and each spec proves that factor
 * reaches the device that cut the rendezvous and no other.
 */

import type { PendingApprovalDescriptor } from '@cipherbox/client';
import type { ApprovalSession } from '@web/auth/deviceApprovalApi';
import { expect, test as base } from '../fixtures';
import { mintIdentity } from '../identity';
import {
  carry,
  openDevice,
  openRelay,
  type ApprovalDevice,
} from '../page-objects/deviceApproval.page';

/** The rendezvous window the API ships, which its own tests hold it to. */
const TTL_MS = 5 * 60 * 1000;

/** The digits a member compares, as the engine groups them. */
const DIGITS = /^\d{6} \d{6} \d{6}$/;

/** A factor is named by its SHA-256, so no assertion here holds one. */
const NAMED = /^[0-9a-f]{64}$/;

/** What the engine calls an answer the approving device did not sign for. */
const BINDING_REFUSED = 'device-response-binding-refused';

/** One account, one identity subject, and the devices that share it. */
interface Account {
  approver: ApprovalDevice;
  requester: ApprovalDevice;
  relay: ApprovalSession;
  /** A further cold device on the same account, for a hostile relay's own. */
  join(): Promise<ApprovalDevice>;
}

/**
 * The approver registers before the relay session is minted: a rendezvous
 * session is issued only for an identity some device on the account can answer
 * for. Every context this opens is closed when the test ends.
 */
const test = base.extend<{ account: Account }>({
  account: async ({ browser, baseURL }, use) => {
    const identity = await mintIdentity(baseURL!);
    const opened: ApprovalDevice[] = [];
    const open = async (signIn = false) => {
      const device = await openDevice(browser, identity.verifierId, signIn);
      opened.push(device);
      return device;
    };

    try {
      const approver = await open(true);
      await approver.register(identity.token);
      await use({
        approver,
        requester: await open(),
        relay: await openRelay(identity.token),
        join: () => open(),
      });
    } finally {
      while (opened.length > 0) await opened.pop()!.close();
    }
  },
});

// An identity token reaches the tab as an `evaluate` argument, and a trace
// records one verbatim. Nothing here reads a failure off a DOM snapshot.
test.use({ trace: 'off' });

/** The row the approver is asked about, once the relay has carried the request. */
async function asked(
  approver: ApprovalDevice,
  requestId: string
): Promise<PendingApprovalDescriptor> {
  let row: PendingApprovalDescriptor | undefined;
  await expect
    .poll(
      async () => {
        row = (await approver.pending()).find((pending) => pending.requestId === requestId);
        return row !== undefined;
      },
      { timeout: 30_000 }
    )
    .toBe(true);
  return row!;
}

test('an approval hands the requester the factor the approver minted', async ({ account }) => {
  const { approver, requester, relay } = account;

  const cut = await requester.cut();
  const { requestId } = await carry(relay, cut);

  const row = await asked(approver, requestId);
  // Both devices derive the same digits from the two fields the requester fixed
  // before it spoke to the relay (ADR 0009 D3).
  expect(cut.comparisonValue).toMatch(DIGITS);
  expect(row.comparisonValue).toBe(cut.comparisonValue);

  const minted = await approver.answer(row, 'approve');
  expect(minted).toMatch(NAMED);

  const answered = await relay.poll(requestId);
  expect(answered.status).toBe('approved');
  if (answered.status !== 'approved') return;
  expect(
    await requester.adopt(
      answered.sealedFactor,
      requestId,
      cut.ephemeralPublicKey,
      answered.responderDevicePublicKey,
      answered.responseSignature
    )
  ).toBe(minted);

  // A settled rendezvous is served once, so a second poll finds nothing.
  expect((await relay.poll(requestId)).status).toBe('gone');
});

test('an answer the approver did not sign is refused before its seal is opened', async ({
  account,
}) => {
  const { approver, requester, relay } = account;

  const cut = await requester.cut();
  const { requestId } = await carry(relay, cut);
  await approver.answer(await asked(approver, requestId), 'approve');
  const answered = await relay.poll(requestId);
  expect(answered.status).toBe('approved');
  if (answered.status !== 'approved') return;

  // The relay keeps the sealed bytes, which open under this device's own
  // scalar, and swaps only the signature. The refusal names the binding rather
  // than the seal (ADR 0009 D4).
  const refused = await requester
    .adopt(
      answered.sealedFactor,
      requestId,
      cut.ephemeralPublicKey,
      answered.responderDevicePublicKey,
      '00'.repeat(64)
    )
    .then(
      () => null,
      (failure: Error) => failure
    );
  expect(refused?.message).toContain(BINDING_REFUSED);
  await requester.forget(cut.ephemeralPublicKey);
});

test('a denial ends the rendezvous', async ({ account }) => {
  const { approver, requester, relay } = account;

  const cut = await requester.cut();
  const { requestId } = await carry(relay, cut);

  await approver.answer(await asked(approver, requestId), 'deny');
  expect((await relay.poll(requestId)).status).toBe('denied');
  await requester.forget(cut.ephemeralPublicKey);

  // The denial retires the row: the account is asked nothing further, and the
  // requester can poll no answer out of it a second time.
  expect((await approver.pending()).map((row) => row.requestId)).not.toContain(requestId);
  expect((await relay.poll(requestId)).status).toBe('gone');
});

test('an abandoned rendezvous is gone, and a live one expires inside the window', async ({
  account,
}) => {
  const { approver, requester, relay } = account;

  const cut = await requester.cut();
  const asking = Date.now();
  const { requestId, expiresAt } = await carry(relay, cut);
  const answeredAt = Date.now();

  // The abuse window the ADR bounds. The API stamps the row inside this pair of
  // readings, so the pair brackets the window with no allowance for skew. The
  // row's own ageing belongs to the API, whose clock is injected there and
  // unreachable from a browser.
  const expiry = Date.parse(expiresAt);
  expect(expiry).toBeGreaterThan(asking);
  expect(expiry).toBeLessThanOrEqual(answeredAt + TTL_MS);

  await asked(approver, requestId);
  await relay.abandon(requestId);
  await requester.forget(cut.ephemeralPublicKey);

  expect((await relay.poll(requestId)).status).toBe('gone');
  await expect
    .poll(async () => (await approver.pending()).map((row) => row.requestId))
    .not.toContain(requestId);
});

test('a substituted ephemeral key shows other digits and its factor does not open', async ({
  account,
}) => {
  const { approver, requester, relay, join } = account;

  // The honest device cuts the rendezvous whose digits its member reads.
  const honest = await requester.cut();
  // A hostile relay cuts its own and carries that one instead. It signs the
  // pair it substituted, so the request signature still verifies — which is why
  // the comparison value, and not the signature, is what tells the two apart.
  const hostile = await join();
  const substitute = await hostile.cut();
  expect(substitute.ephemeralPublicKey).not.toBe(honest.ephemeralPublicKey);

  const { requestId } = await carry(relay, substitute);

  const row = await asked(approver, requestId);
  expect(honest.comparisonValue).toMatch(DIGITS);
  expect(row.comparisonValue).toBe(substitute.comparisonValue);
  expect(row.comparisonValue).not.toBe(honest.comparisonValue);

  // A member who approves without comparing seals the factor to the relay.
  const minted = await approver.answer(row, 'approve');
  expect(minted).toMatch(NAMED);
  const answered = await relay.poll(requestId);
  expect(answered.status).toBe('approved');
  if (answered.status !== 'approved') return;

  // The device the member meant to let in cannot adopt it: the answer is signed
  // over the key that was substituted, and the honest device derives the key
  // that signature must cover from its own scalar...
  const refused = await requester
    .adopt(
      answered.sealedFactor,
      requestId,
      honest.ephemeralPublicKey,
      answered.responderDevicePublicKey,
      answered.responseSignature
    )
    .then(
      () => null,
      (failure: Error) => failure
    );
  expect(refused?.message).toContain(BINDING_REFUSED);
  // ...while the device that substituted the key does open it, which is the
  // whole loss the digits on the two screens are there to stop.
  expect(
    await hostile.adopt(
      answered.sealedFactor,
      requestId,
      substitute.ephemeralPublicKey,
      answered.responderDevicePublicKey,
      answered.responseSignature
    )
  ).toBe(minted);
});
