import { ConflictException, UnauthorizedException } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import { DataSource, EntityManager } from 'typeorm';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createSiweMessage } from 'viem/siwe';
import { beforeEach, describe, expect, it } from 'vitest';
import { FakeClock, FakeEntropy, fakeConfig } from '../../testing/fakes';
import { FakeRepository } from '../../testing/fake-repo';
import { newIdentity, signChallenge } from '../../testing/identities';
import { AccountDevice } from '../../device-approval/entities/account-device.entity';
import { AuthMethod, type AuthMethodKind } from '../entities/auth-method.entity';
import { User } from '../entities/user.entity';
import { AuthService } from './auth.service';
import {
  ChallengeService,
  IDENTITY_CHALLENGE_PREFIXES,
  type IdentityChallengeKind,
  type SiweChallengeKind,
} from './challenge.service';
import { IdentityService } from './identity.service';
import { IdentityTokenService, type VerifiedIdentityToken } from './identity-token.service';
import { SIWE_LINK_STATEMENT, SIWE_LOGIN_STATEMENT, SiweService } from './siwe.service';
import { TokenService } from './token.service';

/**
 * The row LOGIC of the auth-method surface against in-memory repos. The advisory
 * lock and the concurrency it buys are proven on a real Postgres in
 * auth.http.itest.ts; the fake transaction runs inline.
 */
function fakeDataSource(repos: Array<[unknown, unknown]>): DataSource {
  const byEntity = new Map(repos);
  return {
    transaction: (runInTransaction: (manager: unknown) => unknown) =>
      runInTransaction({
        getRepository: (entity: unknown) => byEntity.get(entity),
        query: async () => [],
      }),
  } as unknown as DataSource;
}

function authServiceOver(
  challenges: ChallengeService,
  users: FakeRepository<User>,
  authMethods: FakeRepository<AuthMethod>,
  identityTokens: IdentityTokenService,
  devices = new FakeRepository<AccountDevice>()
): AuthService {
  return new AuthService(
    challenges,
    new IdentityService(),
    new SiweService(fakeConfig({ CORS_ALLOWED_ORIGINS: 'http://localhost:5173' }).service),
    {
      createTokenPair: () =>
        Promise.resolve({ accessToken: 'a', refreshToken: 'r', acceleratorToken: 'x' }),
    } as unknown as TokenService,
    identityTokens,
    new FakeClock(),
    fakeConfig({}).service,
    users as never,
    authMethods as never,
    fakeDataSource([
      [User, users],
      [AuthMethod, authMethods],
      [AccountDevice, devices],
    ])
  );
}

const USER_ID = '11111111-1111-4111-8111-111111111111';
/** A second account's identity key, for the cross-account refusals. */
const OTHER_KEY = '02'.padEnd(66, 'c');

describe('AuthService auth-method surface', () => {
  let authMethods: FakeRepository<AuthMethod>;
  let users: FakeRepository<User>;
  let challenges: ChallengeService;
  let service: AuthService;
  let privateKey: Uint8Array;
  let publicKey: string;

  beforeEach(() => {
    authMethods = new FakeRepository<AuthMethod>();
    users = new FakeRepository<User>();
    challenges = new ChallengeService(new FakeClock(), new FakeEntropy(), fakeConfig({}).service);
    service = authServiceOver(challenges, users, authMethods, {} as IdentityTokenService);

    ({ privateKey, publicKey } = newIdentity());
  });

  /** The account key's answer to a fresh challenge of one operation's kind. */
  function reproof(
    kind: IdentityChallengeKind,
    subject?: string
  ): { challenge: string; challengeSignature: string } {
    const { challenge } = challenges.issueIdentityChallenge(kind, { publicKey, subject });
    return { challenge, challengeSignature: signChallenge(challenge, privateKey) };
  }

  async function seedMethod(kind: AuthMethodKind): Promise<string> {
    const row = await authMethods.save({
      userId: USER_ID,
      kind,
      identifierHash: createHash('sha256').update(`${kind}-${USER_ID}`).digest('hex'),
      identifierDisplay: `${kind}-display`,
    } as Partial<AuthMethod>);
    return row.id;
  }

  function unlink(
    methodId: string,
    kind: IdentityChallengeKind = 'identity-unlink',
    subject: string = methodId
  ): Promise<void> {
    const { challenge, challengeSignature } = reproof(kind, subject);
    return service.unlinkAuthMethod(USER_ID, publicKey, methodId, challenge, challengeSignature);
  }

  it('unlinks a wallet row the caller owns', async () => {
    await seedMethod('identity');
    const wallet = await seedMethod('wallet');

    await unlink(wallet);

    expect(await authMethods.count({ where: { userId: USER_ID } })).toBe(1);
  });

  /**
   * `identityLogin` and `testLogin` authorise off the `users` table and then
   * re-insert their row, so deleting one revokes nothing: the next login through
   * that path recreates it. Refusing is the only honest answer, and the pane's
   * copy promises exactly this revocation.
   */
  it.each(['identity', 'test'] as const)(
    'refuses to unlink a %s row, which its login path would recreate',
    async (kind) => {
      const target = await seedMethod(kind);
      await seedMethod('wallet');

      await expect(unlink(target)).rejects.toThrow(ConflictException);
      expect(await authMethods.count({ where: { userId: USER_ID, kind } })).toBe(1);
    }
  );

  /**
   * A SIWE message over a nonce from the named pool. The link pool binds the
   * minting account, so `mintedFor` names whose session issued the nonce.
   */
  function siweMessage(
    account: ReturnType<typeof privateKeyToAccount>,
    statement: string,
    nonceKind: SiweChallengeKind,
    mintedFor: string | undefined = nonceKind === 'siwe-link' ? publicKey : undefined
  ) {
    const { nonce } = challenges.issueSiweNonce(nonceKind, { publicKey: mintedFor });
    return createSiweMessage({
      address: account.address,
      chainId: 1,
      domain: 'localhost:5173',
      nonce,
      uri: 'http://localhost:5173',
      version: '1',
      statement,
    });
  }

  async function linkWith(
    statement: string,
    proof: { challenge: string; challengeSignature: string },
    nonceKind: SiweChallengeKind = 'siwe-link',
    mintedFor?: string
  ) {
    const account = privateKeyToAccount(generatePrivateKey());
    const message = siweMessage(account, statement, nonceKind, mintedFor);
    const signature = await account.signMessage({ message });
    return service.siweLink(
      USER_ID,
      publicKey,
      message,
      signature,
      proof.challenge,
      proof.challengeSignature
    );
  }

  /** A re-proof the account key never made. */
  const forgedProof = {
    challenge: IDENTITY_CHALLENGE_PREFIXES['identity-link'].padEnd(82, 'f'),
    challengeSignature: '0'.repeat(128),
  };

  it('links a wallet once the account identity key is re-proved', async () => {
    await linkWith(SIWE_LINK_STATEMENT, reproof('identity-link'));
    expect(await authMethods.count({ where: { userId: USER_ID, kind: 'wallet' } })).toBe(1);
  });

  it('refuses a link carrying no valid identity re-proof, and links nothing', async () => {
    await expect(linkWith(SIWE_LINK_STATEMENT, forgedProof)).rejects.toThrow(UnauthorizedException);
    expect(await authMethods.count({ where: { userId: USER_ID } })).toBe(0);
  });

  it('refuses a phished sign-in signature replayed as a link, and links nothing', async () => {
    await expect(linkWith(SIWE_LOGIN_STATEMENT, reproof('identity-link'))).rejects.toThrow(
      UnauthorizedException
    );
    expect(await authMethods.count({ where: { userId: USER_ID } })).toBe(0);
  });

  /**
   * The structural half of the binding, and the reason the statement alone was
   * not enough: the statement here is the one the link route expects, so only
   * the nonce's own kind can refuse this message.
   */
  it('refuses a sign-in nonce spent as a link, statement notwithstanding', async () => {
    await expect(
      linkWith(SIWE_LINK_STATEMENT, reproof('identity-link'), 'siwe-login')
    ).rejects.toThrow(UnauthorizedException);
    expect(await authMethods.count({ where: { userId: USER_ID } })).toBe(0);
  });

  it.each(['identity-login', 'identity-unlink'] as const)(
    'refuses a link re-proved with a %s challenge, and links nothing',
    async (kind) => {
      await expect(linkWith(SIWE_LINK_STATEMENT, reproof(kind))).rejects.toThrow(
        UnauthorizedException
      );
      expect(await authMethods.count({ where: { userId: USER_ID } })).toBe(0);
    }
  );

  /**
   * The link pool binds the minting account, so one member's session cannot
   * spend a nonce another member's session issued — a wallet a victim signed
   * for their own account cannot be redirected onto the attacker's.
   */
  it('refuses a link nonce another account minted, and links nothing', async () => {
    await expect(
      linkWith(SIWE_LINK_STATEMENT, reproof('identity-link'), 'siwe-link', OTHER_KEY)
    ).rejects.toThrow(UnauthorizedException);
    expect(await authMethods.count({ where: { userId: USER_ID } })).toBe(0);
  });

  it.each(['identity-login', 'identity-link'] as const)(
    'refuses an unlink re-proved with a %s challenge, and keeps the row',
    async (kind) => {
      await seedMethod('identity');
      const wallet = await seedMethod('wallet');

      await expect(unlink(wallet, kind, undefined)).rejects.toThrow(UnauthorizedException);
      expect(await authMethods.count({ where: { userId: USER_ID } })).toBe(2);
    }
  );

  /**
   * The signed bytes name the operation, not the row. The mint names the row,
   * so a captured proof cannot be redirected onto a method the member never
   * chose — which is the whole point of re-proving against a stolen bearer.
   */
  it('refuses an unlink redirected onto another row, and keeps both', async () => {
    await seedMethod('identity');
    const first = await seedMethod('wallet');
    const second = await seedMethod('wallet');

    await expect(unlink(second, 'identity-unlink', first)).rejects.toThrow(UnauthorizedException);
    expect(await authMethods.count({ where: { userId: USER_ID } })).toBe(3);
  });

  it.each(['identity-link', 'identity-unlink'] as const)(
    'refuses a login signed against a %s challenge',
    async (kind) => {
      const { challenge, challengeSignature } = reproof(kind);
      await expect(service.identityLogin(publicKey, challenge, challengeSignature)).rejects.toThrow(
        UnauthorizedException
      );
    }
  );
});

describe('AuthService login bind (ADR 0058 D2)', () => {
  let users: FakeRepository<User>;
  let devices: FakeRepository<AccountDevice>;
  let challenges: ChallengeService;
  let service: AuthService;
  let subjects: Map<string, string>;
  let privateKey: Uint8Array;
  let publicKey: string;

  beforeEach(() => {
    users = new FakeRepository<User>();
    devices = new FakeRepository<AccountDevice>();
    challenges = new ChallengeService(new FakeClock(), new FakeEntropy(), fakeConfig({}).service);
    subjects = new Map();
    const identityTokens = {
      verify: async (token: string): Promise<VerifiedIdentityToken> => {
        const subject = subjects.get(token);
        if (!subject) {
          throw new Error('identity token does not verify');
        }
        return { subject, method: 'google', tokenId: randomUUID(), expiresAt: new Date(0) };
      },
    } as unknown as IdentityTokenService;
    service = authServiceOver(
      challenges,
      users,
      new FakeRepository<AuthMethod>(),
      identityTokens,
      devices
    );

    ({ privateKey, publicKey } = newIdentity());
  });

  /** Mints a token that the fake verifier resolves to `subject`. */
  function tokenFor(subject: string): string {
    const token = `token-${randomUUID()}`;
    subjects.set(token, subject);
    return token;
  }

  function login(identityToken?: string) {
    const { challenge } = challenges.issueIdentityChallenge('identity-login', { publicKey });
    return service.identityLogin(
      publicKey,
      challenge,
      signChallenge(challenge, privateKey),
      identityToken
    );
  }

  function seedAccount(key: string, identitySubjectId: string | null): Promise<User> {
    return users.save({ publicKey: key, identitySubjectId });
  }

  function bindOf(key: string): string | null {
    return users.rows.find((row) => row.publicKey === key)?.identitySubjectId ?? null;
  }

  it('binds the subject to an existing unbound account', async () => {
    await seedAccount(publicKey, null);
    const subject = randomUUID();

    const { isNewUser } = await login(tokenFor(subject));

    expect(isNewUser).toBe(false);
    expect(users.rows).toHaveLength(1);
    expect(bindOf(publicKey)).toBe(subject);
  });

  it('binds nothing when a device row of another account holds the subject', async () => {
    const subject = randomUUID();
    const holder = await seedAccount(OTHER_KEY, null);
    await devices.save({ userId: holder.id, identitySubjectId: subject });

    const { isNewUser } = await login(tokenFor(subject));

    expect(isNewUser).toBe(true);
    expect(bindOf(publicKey)).toBeNull();
    expect(bindOf(OTHER_KEY)).toBeNull();
  });

  it('boundSubjectOf returns the bind of the account, or null', async () => {
    const subject = randomUUID();
    const bound = await seedAccount(publicKey, subject);
    const unbound = await seedAccount(OTHER_KEY, null);
    const manager = { getRepository: () => users } as unknown as EntityManager;

    await expect(service.boundSubjectOf(manager, bound.id)).resolves.toBe(subject);
    await expect(service.boundSubjectOf(manager, unbound.id)).resolves.toBeNull();
    await expect(service.boundSubjectOf(manager, randomUUID())).resolves.toBeNull();
  });
});
