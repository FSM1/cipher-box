import { ConflictException, UnauthorizedException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { QueryFailedError } from 'typeorm';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { User } from '../../auth/entities/user.entity';
import { IdentityTokenService } from '../../auth/services/identity-token.service';
import { FakeDataSource } from '../../testing/fake-data-source';
import { FakeRepository } from '../../testing/fake-repo';
import { createTestDeviceKey, TestDeviceKey } from '../../testing/device-keys';
import { FakeClock, fakeConfig } from '../../testing/fakes';
import {
  bootedIdentityTokenService,
  encodedIdentitySigningKey,
  identityTokenWithJti,
  identityTokenWithRawExp,
} from '../../testing/identity-tokens';
import { deviceRegistrationPayload } from '../device-signature';
import { AccountDevice } from '../entities/account-device.entity';
import {
  AccountDeviceService,
  OTHER_SUBJECT_MESSAGE,
  RegisterDeviceInput,
  UNBOUND_ACCOUNT_MESSAGE,
} from './account-device.service';

/** The service's own default; an over-range DEVICE_REGISTRY_CAP falls back to it. */
const DEFAULT_DEVICE_CAP = 20;

function queryFailure(driverError: Record<string, string>): QueryFailedError {
  return new QueryFailedError('INSERT', [], driverError as never);
}

describe('AccountDeviceService', () => {
  let devices: FakeRepository<AccountDevice>;
  let users: FakeRepository<User>;
  let clock: FakeClock;
  let service: AccountDeviceService;
  let subjects: Map<string, string>;
  let spent: Set<string>;
  let account: string;
  let token: string;
  let device: TestDeviceKey;

  /** Mints an identity token the stubbed verifier resolves to `subject`. */
  function mintIdentityToken(subject: string = randomUUID()): string {
    const value = `token-${randomUUID()}`;
    subjects.set(value, subject);
    return value;
  }

  function subjectOf(identityToken: string): string {
    return subjects.get(identityToken) as string;
  }

  /** Seeds the bind that a login writes (ADR 0058 D2): `userId` bound to `subject`. */
  async function bind(userId: string, subject: string | null = subjectOf(token)): Promise<void> {
    await users.save({ id: userId, publicKey: `key-${userId}`, identitySubjectId: subject });
  }

  /**
   * A registration signed by `key` over `signedAccount` (defaults to honest),
   * presenting a fresh token for the identity `token` names: a token is spent.
   */
  function registration(
    key: TestDeviceKey,
    signedAccount: string,
    overrides: Partial<RegisterDeviceInput> = {}
  ): RegisterDeviceInput {
    return {
      publicKey: key.publicKey,
      signature: key.sign(deviceRegistrationPayload(signedAccount, key.publicKey)),
      identityToken: mintIdentityToken(subjectOf(token)),
      ...overrides,
    };
  }

  function build(config: Record<string, string | undefined> = {}) {
    devices = new FakeRepository<AccountDevice>();
    users = new FakeRepository<User>();
    clock = new FakeClock();
    subjects = new Map();
    spent = new Set();
    const identityTokens = {
      verify: async (value: string) => {
        const subject = subjects.get(value);
        if (!subject) {
          throw new Error('identity token does not verify');
        }
        return { subject, method: 'google' as const, tokenId: value, expiresAt: clock.now() };
      },
      spend: async (_manager: unknown, verified: { tokenId: string }) => {
        if (spent.has(verified.tokenId)) {
          throw new UnauthorizedException('Identity token already used');
        }
        spent.add(verified.tokenId);
      },
    } as unknown as IdentityTokenService;
    service = serviceOver(identityTokens, config);
  }

  function serviceOver(
    identityTokens: IdentityTokenService,
    config: Record<string, string | undefined> = {}
  ) {
    return new AccountDeviceService(
      devices as never,
      rollingBackDataSource() as never,
      identityTokens,
      clock,
      fakeConfig(config).service
    );
  }

  /**
   * The fake transaction does not roll back. This one restores the spent set
   * when the work throws, as Postgres does for the spent-token row.
   */
  function rollingBackDataSource() {
    const inner = new FakeDataSource(devices as never, [[User, users as never]]);
    return {
      getRepository: (entity: unknown) => (entity === User ? users : devices),
      transaction: async <T>(work: (manager: unknown) => Promise<T>): Promise<T> => {
        const spentBefore = [...spent];
        try {
          return await inner.transaction(work);
        } catch (error) {
          spent.clear();
          spentBefore.forEach((id) => spent.add(id));
          throw error;
        }
      },
    };
  }

  beforeEach(async () => {
    build();
    account = randomUUID();
    device = createTestDeviceKey();
    token = mintIdentityToken();
    await bind(account);
  });

  describe('register', () => {
    let encodedPem: string;

    beforeAll(() => {
      encodedPem = encodedIdentitySigningKey();
    });

    /** Puts `service` over a real token service, and returns the spy on its `spend`. */
    async function overRealTokens() {
      const realTokens = await bootedIdentityTokenService(
        { NODE_ENV: 'production', IDENTITY_JWT_PRIVATE_KEY: encodedPem },
        clock
      );
      service = serviceOver(realTokens);
      return vi.spyOn(realTokens, 'spend');
    }

    it('creates the row from the proven account, the identity subject and the key', async () => {
      const created = await service.register(
        account,
        registration(device, account, { label: 'A' })
      );

      expect(devices.rows).toHaveLength(1);
      const row = devices.rows[0];
      expect(row.userId).toBe(account);
      expect(row.identitySubjectId).toBe(subjectOf(token));
      expect(row.publicKey).toBe(device.publicKey);
      expect(row.label).toBe('A');
      expect(row.createdAt).toEqual(clock.now());
      expect(row.lastSeenAt).toEqual(clock.now());
      expect(created).toEqual({
        id: row.id,
        publicKey: device.publicKey,
        label: 'A',
        createdAt: clock.now().toISOString(),
        lastSeenAt: clock.now().toISOString(),
      });
    });

    it('stores a null label when none is supplied', async () => {
      await service.register(account, registration(device, account));
      expect(devices.rows[0].label).toBeNull();
    });

    it('refuses a signature bound to a different account id', async () => {
      // The account is inside the signed bytes, so a registration captured on
      // one account cannot be replayed onto another.
      const otherAccount = randomUUID();
      await expect(
        service.register(account, registration(device, otherAccount))
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(devices.rows).toHaveLength(0);
    });

    it('refuses a signature made by a different key', async () => {
      const impostor = createTestDeviceKey();
      await expect(
        service.register(
          account,
          registration(device, account, {
            signature: impostor.sign(deviceRegistrationPayload(account, device.publicKey)),
          })
        )
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(devices.rows).toHaveLength(0);
    });

    it('refuses a malformed signature', async () => {
      await expect(
        service.register(account, registration(device, account, { signature: 'not-hex' }))
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(devices.rows).toHaveLength(0);
    });

    it('refuses an identity token that does not verify', async () => {
      await expect(
        service.register(account, registration(device, account, { identityToken: 'forged' }))
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(devices.rows).toHaveLength(0);
    });

    it('refuses a replayed identity token, and writes nothing', async () => {
      await service.register(account, registration(device, account, { identityToken: token }));

      await expect(
        service.register(
          account,
          registration(createTestDeviceKey(), account, { identityToken: token })
        )
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(devices.rows).toHaveLength(1);
    });

    it('refuses a replayed token before the identity check, so a refusal names the replay', async () => {
      await service.register(account, registration(device, account, { identityToken: token }));

      const otherAccount = randomUUID();
      await expect(
        service.register(
          otherAccount,
          registration(createTestDeviceKey(), otherAccount, { identityToken: token })
        )
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('refuses a token whose token id is not a UUID with 401, before the uuid column sees it', async () => {
      const spend = await overRealTokens();

      const malformed = await identityTokenWithJti(encodedPem, clock, 'not-a-uuid');
      await expect(
        service.register(account, registration(device, account, { identityToken: malformed }))
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(spend).not.toHaveBeenCalled();
      expect(devices.rows).toHaveLength(0);
    });

    it('refuses a token whose expiry is not finite with 401, before any spend', async () => {
      const spend = await overRealTokens();

      const unbounded = await identityTokenWithRawExp(encodedPem, '1e999');
      await expect(
        service.register(account, registration(device, account, { identityToken: unbounded }))
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(spend).not.toHaveBeenCalled();
      expect(devices.rows).toHaveLength(0);
    });

    it('refuses a token whose expiry is past the token lifetime with 401, before any spend', async () => {
      const spend = await overRealTokens();

      const farFuture = await identityTokenWithRawExp(
        encodedPem,
        String(Date.UTC(200_000, 0, 1) / 1000)
      );
      await expect(
        service.register(account, registration(device, account, { identityToken: farFuture }))
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(spend).not.toHaveBeenCalled();
      expect(devices.rows).toHaveLength(0);
    });

    it('is idempotent per key: a re-registration updates rather than duplicates', async () => {
      const first = await service.register(
        account,
        registration(device, account, { label: 'laptop' })
      );
      clock.advanceMs(60_000);
      const second = await service.register(
        account,
        registration(device, account, { label: 'work laptop' })
      );

      expect(devices.rows).toHaveLength(1);
      expect(second.id).toBe(first.id);
      expect(second.label).toBe('work laptop');
      expect(second.createdAt).toBe(first.createdAt);
      expect(second.lastSeenAt).toBe(clock.now().toISOString());
      expect(new Date(second.lastSeenAt).getTime()).toBeGreaterThan(
        new Date(first.lastSeenAt).getTime()
      );
    });

    it('keeps the existing label when a re-registration omits one', async () => {
      await service.register(account, registration(device, account, { label: 'laptop' }));
      const again = await service.register(account, registration(device, account));
      expect(again.label).toBe('laptop');
    });

    it('refuses a re-touch of a row under another subject, and rewrites nothing', async () => {
      const recorded = randomUUID();
      await devices.save({
        userId: account,
        identitySubjectId: recorded,
        publicKey: device.publicKey,
        label: 'A',
      });

      await expect(
        service.register(account, registration(device, account, { label: 'B' }))
      ).rejects.toThrow(new ConflictException('Device key is registered under another identity'));

      expect(devices.rows).toHaveLength(1);
      expect(devices.rows[0].identitySubjectId).toBe(recorded);
      expect(devices.rows[0].label).toBe('A');
    });

    it('rejects a key already registered to another account', async () => {
      await service.register(account, registration(device, account));

      const otherAccount = randomUUID();
      token = mintIdentityToken();
      await bind(otherAccount);
      await expect(
        service.register(otherAccount, registration(device, otherAccount))
      ).rejects.toThrow(new ConflictException('Device key is registered to another account'));
      expect(devices.rows).toHaveLength(1);
      expect(devices.rows[0].userId).toBe(account);
    });

    it('records the bound subject and spends the token for a bound account', async () => {
      const presented = mintIdentityToken(subjectOf(token));

      await service.register(account, registration(device, account, { identityToken: presented }));

      expect(devices.rows).toHaveLength(1);
      expect(devices.rows[0].identitySubjectId).toBe(subjectOf(token));
      expect(spent.has(presented)).toBe(true);
    });

    it('refuses an unbound account with 409, writes no row, and leaves the token unspent', async () => {
      const unbound = randomUUID();
      await bind(unbound, null);
      const presented = mintIdentityToken(subjectOf(token));

      await expect(
        service.register(unbound, registration(device, unbound, { identityToken: presented }))
      ).rejects.toThrow(new ConflictException(UNBOUND_ACCOUNT_MESSAGE));
      expect(devices.rows).toHaveLength(0);
      expect(spent.has(presented)).toBe(false);
    });

    it('refuses a token for another subject with 409, writes no row, and leaves the token unspent', async () => {
      const presented = mintIdentityToken();

      await expect(
        service.register(account, registration(device, account, { identityToken: presented }))
      ).rejects.toThrow(new ConflictException(OTHER_SUBJECT_MESSAGE));
      expect(devices.rows).toHaveLength(0);
      expect(spent.has(presented)).toBe(false);
    });

    it('allows a second device on the same account under the same identity', async () => {
      await service.register(account, registration(device, account));
      const second = createTestDeviceKey();
      await service.register(account, registration(second, account));
      expect(devices.rows).toHaveLength(2);
    });

    it('rejects a registration past the per-account cap', async () => {
      build({ DEVICE_REGISTRY_CAP: '2' });
      token = mintIdentityToken();
      await bind(account);
      const first = createTestDeviceKey();
      const second = createTestDeviceKey();
      await service.register(account, registration(first, account));
      await service.register(account, registration(second, account));

      await expect(
        service.register(account, registration(createTestDeviceKey(), account))
      ).rejects.toBeInstanceOf(ConflictException);
      expect(devices.rows).toHaveLength(2);
    });

    it('holds the default cap when the configured one is over range', async () => {
      build({ DEVICE_REGISTRY_CAP: '100000' });
      token = mintIdentityToken();
      await bind(account);
      for (let i = 0; i < DEFAULT_DEVICE_CAP; i += 1) {
        await service.register(account, registration(createTestDeviceKey(), account));
      }

      await expect(
        service.register(account, registration(createTestDeviceKey(), account))
      ).rejects.toBeInstanceOf(ConflictException);
      expect(devices.rows).toHaveLength(DEFAULT_DEVICE_CAP);
    });

    it('answers a lost public-key race from the committed winner', async () => {
      await service.register(account, registration(device, account, { label: 'first' }));
      const winner = devices.rows[0];
      vi.spyOn(devices, 'save').mockRejectedValueOnce(
        queryFailure({ code: '23505', constraint: 'uq_account_devices_public_key' })
      );

      const answered = await service.register(account, registration(device, account));
      expect(answered.id).toBe(winner.id);
      expect(devices.rows).toHaveLength(1);
    });

    it('surfaces a constraint violation that is not that race, rather than reporting success', async () => {
      const failure = queryFailure({
        code: '23503',
        constraint: 'FK_3456d8a033130685cb3653fdab9',
      });
      vi.spyOn(devices, 'save').mockRejectedValueOnce(failure);

      await expect(service.register(account, registration(device, account))).rejects.toBe(failure);
      expect(devices.rows).toHaveLength(0);
    });

    it('lets an already-registered key re-touch at the cap', async () => {
      build({ DEVICE_REGISTRY_CAP: '1' });
      token = mintIdentityToken();
      await bind(account);
      await service.register(account, registration(device, account, { label: 'only' }));
      clock.advanceMs(1000);

      const again = await service.register(
        account,
        registration(device, account, { label: 'sti' })
      );
      expect(devices.rows).toHaveLength(1);
      expect(again.label).toBe('sti');
      expect(again.lastSeenAt).toBe(clock.now().toISOString());
    });
  });

  describe('list', () => {
    it('returns only the caller devices, oldest first', async () => {
      const first = createTestDeviceKey();
      const second = createTestDeviceKey();
      await service.register(account, registration(first, account, { label: 'first' }));
      clock.advanceMs(1000);
      await service.register(account, registration(second, account, { label: 'second' }));

      const otherAccount = randomUUID();
      const foreign = createTestDeviceKey();
      token = mintIdentityToken();
      await bind(otherAccount);
      await service.register(otherAccount, registration(foreign, otherAccount));

      const listed = await service.list(account);
      expect(listed.map((entry) => entry.label)).toEqual(['first', 'second']);
      expect(listed.map((entry) => entry.publicKey)).toEqual([first.publicKey, second.publicKey]);
    });

    it('returns an empty list for an account with no devices', async () => {
      await expect(service.list(randomUUID())).resolves.toEqual([]);
    });
  });

  describe('revoke', () => {
    it('hard-deletes the caller own device row', async () => {
      const { id } = await service.register(account, registration(device, account));
      await service.revoke(account, id);
      expect(devices.rows).toHaveLength(0);
    });

    it('leaves another account device intact and reveals nothing', async () => {
      const { id } = await service.register(account, registration(device, account));
      await expect(service.revoke(randomUUID(), id)).resolves.toBeUndefined();
      expect(devices.rows).toHaveLength(1);
      expect(devices.rows[0].id).toBe(id);
    });

    it('is a silent no-op for a malformed or absent id', async () => {
      await service.register(account, registration(device, account));
      await expect(service.revoke(account, 'not-a-uuid')).resolves.toBeUndefined();
      await expect(service.revoke(account, randomUUID())).resolves.toBeUndefined();
      expect(devices.rows).toHaveLength(1);
    });
  });

  describe('isRegistered', () => {
    it('reports a registered key for its own account', async () => {
      await service.register(account, registration(device, account));
      await expect(service.isRegistered(account, device.publicKey)).resolves.toBe(true);
    });

    it('is scoped to the account: the same key under another account is not registered', async () => {
      await service.register(account, registration(device, account));
      await expect(service.isRegistered(randomUUID(), device.publicKey)).resolves.toBe(false);
    });

    it('reports an unknown key as not registered', async () => {
      await expect(service.isRegistered(account, createTestDeviceKey().publicKey)).resolves.toBe(
        false
      );
    });
  });
});
