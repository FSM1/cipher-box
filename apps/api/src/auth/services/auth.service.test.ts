import { ConflictException, UnauthorizedException } from '@nestjs/common';
import { secp256k1 } from '@noble/curves/secp256k1';
import { createHash } from 'node:crypto';
import { DataSource } from 'typeorm';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createSiweMessage } from 'viem/siwe';
import { beforeEach, describe, expect, it } from 'vitest';
import { FakeClock, FakeEntropy, fakeConfig } from '../../testing/fakes';
import { FakeRepository } from '../../testing/fake-repo';
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

const USER_ID = '11111111-1111-4111-8111-111111111111';
/** A second account's identity key, for the cross-account refusals. */
const OTHER_KEY = '02'.padEnd(66, 'c');

describe('AuthService auth-method surface', () => {
  let authMethods: FakeRepository<AuthMethod>;
  let users: FakeRepository<User>;
  let challenges: ChallengeService;
  let identities: IdentityService;
  let service: AuthService;
  let privateKey: Uint8Array;
  let publicKey: string;

  beforeEach(() => {
    authMethods = new FakeRepository<AuthMethod>();
    users = new FakeRepository<User>();
    challenges = new ChallengeService(new FakeClock(), new FakeEntropy(), fakeConfig({}).service);
    identities = new IdentityService();
    service = new AuthService(
      challenges,
      identities,
      new SiweService(fakeConfig({ CORS_ALLOWED_ORIGINS: 'http://localhost:5173' }).service),
      {
        createTokenPair: () =>
          Promise.resolve({ accessToken: 'a', refreshToken: 'r', acceleratorToken: 'x' }),
      } as unknown as TokenService,
      new FakeClock(),
      fakeConfig({}).service,
      users as never,
      authMethods as never,
      fakeDataSource([
        [User, users],
        [AuthMethod, authMethods],
      ])
    );

    privateKey = secp256k1.utils.randomPrivateKey();
    publicKey = Buffer.from(secp256k1.getPublicKey(privateKey, true)).toString('hex');
  });

  /** The account key's answer to a fresh challenge of one operation's kind. */
  function reproof(
    kind: IdentityChallengeKind,
    subject?: string
  ): { challenge: string; challengeSignature: string } {
    const { challenge } = challenges.issueIdentityChallenge(kind, { publicKey, subject });
    const hash = createHash('sha256').update(challenge, 'utf8').digest();
    return { challenge, challengeSignature: secp256k1.sign(hash, privateKey).toCompactHex() };
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
