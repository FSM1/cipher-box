import {
  BadRequestException,
  ConflictException,
  NotFoundException,
  PayloadTooLargeException,
  UnauthorizedException,
} from '@nestjs/common';
import { secp256k1 } from '@noble/curves/secp256k1';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { IdentityTokenService } from '../../auth/services/identity-token.service';
import { TokenService } from '../../auth/services/token.service';
import { FakeDataSource } from '../../testing/fake-data-source';
import { FakeRepository } from '../../testing/fake-repo';
import { createTestDeviceKey, TestDeviceKey } from '../../testing/device-keys';
import { FakeClock, fakeConfig } from '../../testing/fakes';
import { approvalRequestPayload, approvalResponsePayload } from '../device-signature';
import { DeviceApproval } from '../entities/device-approval.entity';
import { AccountDeviceService } from './account-device.service';
import { DeviceApprovalService } from './device-approval.service';

/** Compressed secp256k1 key, the shape the ephemeral seal target takes. */
function newEphemeralKey(): string {
  const priv = secp256k1.utils.randomPrivateKey();
  return Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
}

function sealedBytes(length: number): string {
  return Buffer.alloc(length, 9).toString('base64');
}

const TTL_MS = 5 * 60 * 1000;
const USER_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_USER_ID = '22222222-2222-4222-8222-222222222222';

describe('DeviceApprovalService', () => {
  let approvals: FakeRepository<DeviceApproval>;
  let clock: FakeClock;
  let service: DeviceApprovalService;
  let registered: Set<string>;
  let accountForSubject: ReturnType<typeof vi.fn>;
  let verifyIdentityToken: ReturnType<typeof vi.fn>;
  let createScopedToken: ReturnType<typeof vi.fn>;
  let requester: TestDeviceKey;
  let approver: TestDeviceKey;
  let ephemeral: string;

  function build(config: Record<string, string | undefined> = {}) {
    approvals = new FakeRepository<DeviceApproval>();
    clock = new FakeClock();
    registered = new Set<string>();
    accountForSubject = vi.fn().mockResolvedValue(USER_ID);
    verifyIdentityToken = vi.fn().mockResolvedValue({ subject: 'subject-1', method: 'google' });
    createScopedToken = vi.fn().mockResolvedValue({ accessToken: 'scoped.jwt', expiresIn: 600 });

    const devices = {
      accountForIdentitySubject: accountForSubject,
      isRegistered: vi.fn(async (_userId: string, publicKey: string) => registered.has(publicKey)),
    } as unknown as AccountDeviceService;

    service = new DeviceApprovalService(
      approvals as never,
      new FakeDataSource(approvals as never, [[DeviceApproval, approvals as never]]) as never,
      devices,
      { verify: verifyIdentityToken } as unknown as IdentityTokenService,
      { createScopedToken } as unknown as TokenService,
      clock,
      fakeConfig(config).service
    );
  }

  /** Open a rendezvous the way a real requester would: signed over its ephemeral key. */
  async function openRendezvous(
    device: TestDeviceKey = requester,
    ephemeralKey: string = ephemeral,
    userId: string = USER_ID
  ) {
    return service.createRequest(userId, {
      devicePublicKey: device.publicKey,
      ephemeralPublicKey: ephemeralKey,
      signature: device.sign(approvalRequestPayload(device.publicKey, ephemeralKey)),
    });
  }

  function signResponse(
    device: TestDeviceKey,
    requestId: string,
    decision: 'approve' | 'deny',
    ephemeralKey: string,
    sealedFactor = ''
  ): string {
    return device.sign(
      approvalResponsePayload({
        devicePublicKey: device.publicKey,
        requestId,
        decision,
        ephemeralPublicKey: ephemeralKey,
        sealedFactor,
      })
    );
  }

  beforeEach(async () => {
    build();
    requester = createTestDeviceKey();
    approver = createTestDeviceKey();
    registered.add(approver.publicKey);
    ephemeral = newEphemeralKey();
  });

  describe('openSession', () => {
    it('mints a device-approval scoped token for an identity a registered device can approve', async () => {
      const token = await service.openSession('identity.jwt');
      expect(token).toEqual({ accessToken: 'scoped.jwt', expiresIn: 600 });
      expect(createScopedToken).toHaveBeenCalledWith(USER_ID, 'device-approval');
    });

    it('asks for no account pseudonym when minting the token', async () => {
      await service.openSession('identity.jwt');
      expect(createScopedToken).toHaveBeenCalledTimes(1);
      expect(createScopedToken.mock.calls[0]).toHaveLength(2);
    });

    it('refuses an identity token that does not verify', async () => {
      verifyIdentityToken.mockRejectedValue(new Error('bad token'));
      await expect(service.openSession('forged.jwt')).rejects.toBeInstanceOf(UnauthorizedException);
      expect(createScopedToken).not.toHaveBeenCalled();
    });

    it('refuses an identity no registered device can approve, rather than opening an empty rendezvous', async () => {
      accountForSubject.mockResolvedValue(null);
      await expect(service.openSession('identity.jwt')).rejects.toBeInstanceOf(NotFoundException);
      expect(createScopedToken).not.toHaveBeenCalled();
    });

    it('scopes the token to the account the device registry names, not the identity subject', async () => {
      accountForSubject.mockResolvedValue(OTHER_USER_ID);
      await service.openSession('identity.jwt');
      expect(createScopedToken).toHaveBeenCalledWith(OTHER_USER_ID, 'device-approval');
    });
  });

  describe('createRequest', () => {
    it('stores a pending rendezvous bound to the device key, the ephemeral key and the signature', async () => {
      const signature = requester.sign(approvalRequestPayload(requester.publicKey, ephemeral));
      const { requestId, expiresAt } = await service.createRequest(USER_ID, {
        devicePublicKey: requester.publicKey,
        ephemeralPublicKey: ephemeral,
        signature,
      });

      expect(approvals.rows).toHaveLength(1);
      const row = approvals.rows[0];
      expect(row.id).toBe(requestId);
      expect(row.userId).toBe(USER_ID);
      expect(row.status).toBe('pending');
      expect(row.requesterDevicePublicKey).toBe(requester.publicKey);
      expect(row.ephemeralPublicKey).toBe(ephemeral);
      expect(row.requestSignature).toBe(signature);
      expect(row.sealedFactor).toBeNull();
      expect(row.responderDevicePublicKey).toBeNull();
      expect(row.responseSignature).toBeNull();
      // Both stamps come from the injected Clock, not the wall clock.
      expect(row.createdAt.getTime()).toBe(clock.now().getTime());
      expect(row.expiresAt.getTime()).toBe(clock.now().getTime() + TTL_MS);
      expect(expiresAt).toBe(row.expiresAt.toISOString());
    });

    it('honors a configured TTL', async () => {
      build({ DEVICE_APPROVAL_TTL_MS: '60000' });
      await openRendezvous();
      expect(approvals.rows[0].expiresAt.getTime()).toBe(clock.now().getTime() + 60000);
    });

    it('refuses an unsigned request', async () => {
      await expect(
        service.createRequest(USER_ID, {
          devicePublicKey: requester.publicKey,
          ephemeralPublicKey: ephemeral,
          signature: '',
        })
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(approvals.rows).toHaveLength(0);
    });

    it('refuses a request signed over a different ephemeral key than the one it offers', async () => {
      const substituted = newEphemeralKey();
      await expect(
        service.createRequest(USER_ID, {
          devicePublicKey: requester.publicKey,
          ephemeralPublicKey: substituted,
          signature: requester.sign(approvalRequestPayload(requester.publicKey, ephemeral)),
        })
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(approvals.rows).toHaveLength(0);
    });

    it('refuses a request signed by a device key other than the one it claims', async () => {
      const impostor = createTestDeviceKey();
      await expect(
        service.createRequest(USER_ID, {
          devicePublicKey: requester.publicKey,
          ephemeralPublicKey: ephemeral,
          signature: impostor.sign(approvalRequestPayload(requester.publicKey, ephemeral)),
        })
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(approvals.rows).toHaveLength(0);
    });

    it('refuses once the account is at its pending cap', async () => {
      build({ DEVICE_APPROVAL_PENDING_CAP: '2' });
      await openRendezvous(requester, newEphemeralKey());
      await openRendezvous(requester, newEphemeralKey());
      await expect(openRendezvous(requester, newEphemeralKey())).rejects.toBeInstanceOf(
        ConflictException
      );
      expect(approvals.rows).toHaveLength(2);
    });

    it('purges expired rows before counting, so a cap full of stale rows still accepts', async () => {
      build({ DEVICE_APPROVAL_PENDING_CAP: '2' });
      await openRendezvous(requester, newEphemeralKey());
      await openRendezvous(requester, newEphemeralKey());
      clock.advanceMs(TTL_MS + 1);

      const { requestId } = await openRendezvous(requester, newEphemeralKey());
      expect(approvals.rows).toHaveLength(1);
      expect(approvals.rows[0].id).toBe(requestId);
    });

    it('counts the cap per account', async () => {
      build({ DEVICE_APPROVAL_PENDING_CAP: '1' });
      await openRendezvous(requester, newEphemeralKey(), USER_ID);
      await expect(
        openRendezvous(requester, newEphemeralKey(), OTHER_USER_ID)
      ).resolves.toMatchObject({ requestId: expect.any(String) });
      expect(approvals.rows).toHaveLength(2);
    });
  });

  describe('status', () => {
    it('reports a pending rendezvous without any sealed material', async () => {
      const { requestId } = await openRendezvous();
      const status = await service.status(USER_ID, requestId);
      expect(status.status).toBe('pending');
      expect(status.ephemeralPublicKey).toBe(ephemeral);
      expect(status.sealedFactor).toBeUndefined();
      expect(status.responderDevicePublicKey).toBeUndefined();
      expect(status.responseSignature).toBeUndefined();
      expect(approvals.rows).toHaveLength(1);
    });

    it('serves an approved rendezvous exactly once, then the row is gone', async () => {
      const { requestId } = await openRendezvous();
      const sealed = sealedBytes(125);
      await service.respond(USER_ID, requestId, {
        decision: 'approve',
        devicePublicKey: approver.publicKey,
        sealedFactor: sealed,
        signature: signResponse(approver, requestId, 'approve', ephemeral, sealed),
      });

      const status = await service.status(USER_ID, requestId);
      expect(status.status).toBe('approved');
      expect(status.sealedFactor).toBe(sealed);
      expect(status.responderDevicePublicKey).toBe(approver.publicKey);
      expect(status.responseSignature).toBeTruthy();

      // Collection ends the row's life: sealed material is never re-fetchable.
      expect(approvals.rows).toHaveLength(0);
      await expect(service.status(USER_ID, requestId)).rejects.toBeInstanceOf(NotFoundException);
    });

    it('serves a denial exactly once, then the row is gone', async () => {
      const { requestId } = await openRendezvous();
      await service.respond(USER_ID, requestId, {
        decision: 'deny',
        devicePublicKey: approver.publicKey,
        signature: signResponse(approver, requestId, 'deny', ephemeral),
      });

      const status = await service.status(USER_ID, requestId);
      expect(status.status).toBe('denied');
      expect(status.sealedFactor).toBeUndefined();
      expect(approvals.rows).toHaveLength(0);
      await expect(service.status(USER_ID, requestId)).rejects.toBeInstanceOf(NotFoundException);
    });

    it('deletes and disowns a rendezvous past its expiry', async () => {
      const { requestId } = await openRendezvous();
      clock.advanceMs(TTL_MS);
      await expect(service.status(USER_ID, requestId)).rejects.toBeInstanceOf(NotFoundException);
      expect(approvals.rows).toHaveLength(0);
    });

    it('does not serve another account rendezvous', async () => {
      const { requestId } = await openRendezvous();
      await expect(service.status(OTHER_USER_ID, requestId)).rejects.toBeInstanceOf(
        NotFoundException
      );
      expect(approvals.rows).toHaveLength(1);
    });

    it('refuses a malformed id without touching the repository', async () => {
      const findOne = vi.spyOn(approvals, 'findOne');
      await expect(service.status(USER_ID, 'not-a-uuid')).rejects.toBeInstanceOf(NotFoundException);
      expect(findOne).not.toHaveBeenCalled();
    });
  });

  describe('respond', () => {
    it('records an approval with the sealed bytes, the responder key and the response signature', async () => {
      const { requestId } = await openRendezvous();
      const sealed = sealedBytes(125);
      const signature = signResponse(approver, requestId, 'approve', ephemeral, sealed);

      await service.respond(USER_ID, requestId, {
        decision: 'approve',
        devicePublicKey: approver.publicKey,
        sealedFactor: sealed,
        signature,
      });

      const row = approvals.rows[0];
      expect(row.status).toBe('approved');
      expect(row.sealedFactor?.toString('base64')).toBe(sealed);
      expect(row.responderDevicePublicKey).toBe(approver.publicKey);
      expect(row.responseSignature).toBe(signature);
    });

    it('records a denial and stores no sealed bytes', async () => {
      const { requestId } = await openRendezvous();
      await service.respond(USER_ID, requestId, {
        decision: 'deny',
        devicePublicKey: approver.publicKey,
        signature: signResponse(approver, requestId, 'deny', ephemeral),
      });
      expect(approvals.rows[0].status).toBe('denied');
      expect(approvals.rows[0].sealedFactor).toBeNull();
    });

    it('refuses a response signed over a different ephemeral key than the stored one', async () => {
      // The substitution defence: assent is checked against the key the
      // requester actually signed for, never the one the responder reports.
      const { requestId } = await openRendezvous();
      const sealed = sealedBytes(125);
      const substituted = newEphemeralKey();

      await expect(
        service.respond(USER_ID, requestId, {
          decision: 'approve',
          devicePublicKey: approver.publicKey,
          sealedFactor: sealed,
          signature: signResponse(approver, requestId, 'approve', substituted, sealed),
        })
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(approvals.rows[0].status).toBe('pending');
      expect(approvals.rows[0].sealedFactor).toBeNull();
    });

    it('refuses a response whose signature covers different sealed bytes than it carries', async () => {
      const { requestId } = await openRendezvous();
      await expect(
        service.respond(USER_ID, requestId, {
          decision: 'approve',
          devicePublicKey: approver.publicKey,
          sealedFactor: sealedBytes(125),
          signature: signResponse(approver, requestId, 'approve', ephemeral, sealedBytes(64)),
        })
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(approvals.rows[0].status).toBe('pending');
    });

    it('refuses a response bound to a different request id', async () => {
      const first = await openRendezvous(requester, newEphemeralKey());
      const second = await openRendezvous(requester, ephemeral);
      const sealed = sealedBytes(125);
      await expect(
        service.respond(USER_ID, second.requestId, {
          decision: 'approve',
          devicePublicKey: approver.publicKey,
          sealedFactor: sealed,
          signature: signResponse(approver, first.requestId, 'approve', ephemeral, sealed),
        })
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(approvals.rows.every((row) => row.status === 'pending')).toBe(true);
    });

    it('refuses an unsigned response', async () => {
      const { requestId } = await openRendezvous();
      await expect(
        service.respond(USER_ID, requestId, {
          decision: 'approve',
          devicePublicKey: approver.publicKey,
          sealedFactor: sealedBytes(125),
          signature: '',
        })
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(approvals.rows[0].status).toBe('pending');
    });

    it('refuses a device that is not registered to this account', async () => {
      const { requestId } = await openRendezvous();
      const stranger = createTestDeviceKey();
      const sealed = sealedBytes(125);
      await expect(
        service.respond(USER_ID, requestId, {
          decision: 'approve',
          devicePublicKey: stranger.publicKey,
          sealedFactor: sealed,
          signature: signResponse(stranger, requestId, 'approve', ephemeral, sealed),
        })
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(approvals.rows[0].status).toBe('pending');
    });

    it('refuses a device approving its own request', async () => {
      registered.add(requester.publicKey);
      const { requestId } = await openRendezvous();
      const sealed = sealedBytes(125);
      await expect(
        service.respond(USER_ID, requestId, {
          decision: 'approve',
          devicePublicKey: requester.publicKey,
          sealedFactor: sealed,
          signature: signResponse(requester, requestId, 'approve', ephemeral, sealed),
        })
      ).rejects.toBeInstanceOf(BadRequestException);
      expect(approvals.rows[0].status).toBe('pending');
    });

    it('refuses an approval carrying no sealed factor', async () => {
      const { requestId } = await openRendezvous();
      await expect(
        service.respond(USER_ID, requestId, {
          decision: 'approve',
          devicePublicKey: approver.publicKey,
          signature: signResponse(approver, requestId, 'approve', ephemeral),
        })
      ).rejects.toBeInstanceOf(BadRequestException);
      expect(approvals.rows[0].status).toBe('pending');
    });

    it('refuses an approval whose sealed factor decodes to nothing', async () => {
      const { requestId } = await openRendezvous();
      await expect(
        service.respond(USER_ID, requestId, {
          decision: 'approve',
          devicePublicKey: approver.publicKey,
          sealedFactor: '',
          signature: signResponse(approver, requestId, 'approve', ephemeral),
        })
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    // The signature covers the sealedFactor TEXT, so a spelling that does not
    // survive a decode/re-encode round trip would be served back as a different
    // string than the approver signed.
    it.each([
      ['unpadded', Buffer.alloc(4, 9).toString('base64').replace(/=+$/, '')],
      ['a non-canonical trailing quartet', 'AB=='],
    ])('refuses a sealed factor spelled %s', async (_label, sealed) => {
      const { requestId } = await openRendezvous();
      await expect(
        service.respond(USER_ID, requestId, {
          decision: 'approve',
          devicePublicKey: approver.publicKey,
          sealedFactor: sealed,
          signature: signResponse(approver, requestId, 'approve', ephemeral, sealed),
        })
      ).rejects.toBeInstanceOf(BadRequestException);
      expect(approvals.rows[0].status).toBe('pending');
      expect(approvals.rows[0].sealedFactor).toBeNull();
    });

    it.each([
      ['the padded spelling of the unpadded rejection', Buffer.alloc(4, 9).toString('base64')],
      ['the canonical spelling of AB==', 'AA=='],
    ])('accepts %s', async (_label, sealed) => {
      const { requestId } = await openRendezvous();
      await service.respond(USER_ID, requestId, {
        decision: 'approve',
        devicePublicKey: approver.publicKey,
        sealedFactor: sealed,
        signature: signResponse(approver, requestId, 'approve', ephemeral, sealed),
      });
      expect(approvals.rows[0].status).toBe('approved');
      expect(approvals.rows[0].sealedFactor?.toString('base64')).toBe(sealed);
    });

    it('refuses a denial that carries a sealed factor', async () => {
      const { requestId } = await openRendezvous();
      const sealed = sealedBytes(125);
      await expect(
        service.respond(USER_ID, requestId, {
          decision: 'deny',
          devicePublicKey: approver.publicKey,
          sealedFactor: sealed,
          signature: signResponse(approver, requestId, 'deny', ephemeral, sealed),
        })
      ).rejects.toBeInstanceOf(BadRequestException);
      expect(approvals.rows[0].status).toBe('pending');
    });

    it('refuses a sealed factor over 1 KiB', async () => {
      const { requestId } = await openRendezvous();
      const sealed = sealedBytes(1025);
      await expect(
        service.respond(USER_ID, requestId, {
          decision: 'approve',
          devicePublicKey: approver.publicKey,
          sealedFactor: sealed,
          signature: signResponse(approver, requestId, 'approve', ephemeral, sealed),
        })
      ).rejects.toBeInstanceOf(PayloadTooLargeException);
      expect(approvals.rows[0].status).toBe('pending');
    });

    it('accepts a sealed factor at exactly the 1 KiB bound', async () => {
      const { requestId } = await openRendezvous();
      const sealed = sealedBytes(1024);
      await service.respond(USER_ID, requestId, {
        decision: 'approve',
        devicePublicKey: approver.publicKey,
        sealedFactor: sealed,
        signature: signResponse(approver, requestId, 'approve', ephemeral, sealed),
      });
      expect(approvals.rows[0].status).toBe('approved');
    });

    it('refuses to answer a rendezvous that is already answered', async () => {
      const { requestId } = await openRendezvous();
      const sealed = sealedBytes(125);
      await service.respond(USER_ID, requestId, {
        decision: 'approve',
        devicePublicKey: approver.publicKey,
        sealedFactor: sealed,
        signature: signResponse(approver, requestId, 'approve', ephemeral, sealed),
      });

      await expect(
        service.respond(USER_ID, requestId, {
          decision: 'deny',
          devicePublicKey: approver.publicKey,
          signature: signResponse(approver, requestId, 'deny', ephemeral),
        })
      ).rejects.toBeInstanceOf(NotFoundException);
      // The first answer stands: a second responder cannot overwrite it.
      expect(approvals.rows[0].status).toBe('approved');
      expect(approvals.rows[0].sealedFactor?.toString('base64')).toBe(sealed);
    });

    it('deletes and disowns an expired rendezvous rather than answering it', async () => {
      const { requestId } = await openRendezvous();
      clock.advanceMs(TTL_MS);
      const sealed = sealedBytes(125);
      await expect(
        service.respond(USER_ID, requestId, {
          decision: 'approve',
          devicePublicKey: approver.publicKey,
          sealedFactor: sealed,
          signature: signResponse(approver, requestId, 'approve', ephemeral, sealed),
        })
      ).rejects.toBeInstanceOf(NotFoundException);
      expect(approvals.rows).toHaveLength(0);
    });

    it('will not answer another account rendezvous', async () => {
      const { requestId } = await openRendezvous();
      const sealed = sealedBytes(125);
      await expect(
        service.respond(OTHER_USER_ID, requestId, {
          decision: 'approve',
          devicePublicKey: approver.publicKey,
          sealedFactor: sealed,
          signature: signResponse(approver, requestId, 'approve', ephemeral, sealed),
        })
      ).rejects.toBeInstanceOf(NotFoundException);
      expect(approvals.rows[0].status).toBe('pending');
    });

    it('refuses a malformed id without touching the repository', async () => {
      const findOne = vi.spyOn(approvals, 'findOne');
      await expect(
        service.respond(USER_ID, 'not-a-uuid', {
          decision: 'deny',
          devicePublicKey: approver.publicKey,
          signature: 'deadbeef',
        })
      ).rejects.toBeInstanceOf(NotFoundException);
      expect(findOne).not.toHaveBeenCalled();
    });
  });

  describe('cancel', () => {
    it('hard-deletes the caller rendezvous', async () => {
      const { requestId } = await openRendezvous();
      await service.cancel(USER_ID, requestId);
      expect(approvals.rows).toHaveLength(0);
    });

    it('leaves another account rendezvous alone', async () => {
      const { requestId } = await openRendezvous();
      await service.cancel(OTHER_USER_ID, requestId);
      expect(approvals.rows).toHaveLength(1);
    });

    it('is a no-op for a malformed id, without touching the repository', async () => {
      await openRendezvous();
      const deleteSpy = vi.spyOn(approvals, 'delete');
      await expect(service.cancel(USER_ID, 'not-a-uuid')).resolves.toBeUndefined();
      expect(deleteSpy).not.toHaveBeenCalled();
      expect(approvals.rows).toHaveLength(1);
    });
  });

  describe('pending', () => {
    it('lists the account pending rendezvous oldest-first', async () => {
      const first = await openRendezvous(requester, newEphemeralKey());
      clock.advanceMs(1000);
      const second = await openRendezvous(requester, newEphemeralKey());

      const listed = await service.pending(USER_ID);
      expect(listed.map((entry) => entry.requestId)).toEqual([first.requestId, second.requestId]);
      expect(new Date(listed[0].createdAt).getTime()).toBeLessThan(
        new Date(listed[1].createdAt).getTime()
      );
    });

    it('carries the requester key, the ephemeral key and the request signature so the approver can re-verify the binding', async () => {
      const signature = requester.sign(approvalRequestPayload(requester.publicKey, ephemeral));
      const { requestId, expiresAt } = await service.createRequest(USER_ID, {
        devicePublicKey: requester.publicKey,
        ephemeralPublicKey: ephemeral,
        signature,
      });

      const [entry] = await service.pending(USER_ID);
      expect(entry).toEqual({
        requestId,
        requesterDevicePublicKey: requester.publicKey,
        ephemeralPublicKey: ephemeral,
        requestSignature: signature,
        createdAt: clock.now().toISOString(),
        expiresAt,
      });
    });

    it('lists only this account rendezvous', async () => {
      await openRendezvous(requester, newEphemeralKey(), USER_ID);
      await openRendezvous(requester, newEphemeralKey(), OTHER_USER_ID);
      const listed = await service.pending(USER_ID);
      expect(listed).toHaveLength(1);
    });

    it('purges expired rendezvous before listing', async () => {
      await openRendezvous(requester, newEphemeralKey());
      clock.advanceMs(TTL_MS + 1);
      const fresh = await openRendezvous(requester, newEphemeralKey());

      const listed = await service.pending(USER_ID);
      expect(listed.map((entry) => entry.requestId)).toEqual([fresh.requestId]);
      expect(approvals.rows).toHaveLength(1);
    });

    it('omits an already-answered rendezvous', async () => {
      const { requestId } = await openRendezvous();
      const sealed = sealedBytes(125);
      await service.respond(USER_ID, requestId, {
        decision: 'approve',
        devicePublicKey: approver.publicKey,
        sealedFactor: sealed,
        signature: signResponse(approver, requestId, 'approve', ephemeral, sealed),
      });
      await expect(service.pending(USER_ID)).resolves.toEqual([]);
    });
  });
});
