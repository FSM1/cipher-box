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
import { ChallengeService } from './challenge.service';
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

describe('AuthService auth-method surface', () => {
  let authMethods: FakeRepository<AuthMethod>;
  let challenges: ChallengeService;
  let identities: IdentityService;
  let service: AuthService;
  let privateKey: Uint8Array;
  let publicKey: string;

  beforeEach(() => {
    authMethods = new FakeRepository<AuthMethod>();
    const users = new FakeRepository<User>();
    challenges = new ChallengeService(new FakeClock(), new FakeEntropy(), fakeConfig({}).service);
    identities = new IdentityService();
    service = new AuthService(
      challenges,
      identities,
      new SiweService(fakeConfig({ CORS_ALLOWED_ORIGINS: 'http://localhost:5173' }).service),
      {} as unknown as TokenService,
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

  /** The account key's answer to a fresh challenge, as link and unlink demand. */
  function reproof(): { challenge: string; challengeSignature: string } {
    const { challenge } = challenges.issueIdentityChallenge(publicKey);
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

  function unlink(methodId: string): Promise<void> {
    const { challenge, challengeSignature } = reproof();
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

  function siweMessage(account: ReturnType<typeof privateKeyToAccount>, statement: string) {
    const { nonce } = challenges.issueSiweNonce();
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

  async function linkWith(statement: string, reproved: boolean) {
    const account = privateKeyToAccount(generatePrivateKey());
    const message = siweMessage(account, statement);
    const signature = await account.signMessage({ message });
    const proof = reproved
      ? reproof()
      : { challenge: 'cipherbox-login:v2:'.padEnd(82, 'f'), challengeSignature: '0'.repeat(128) };
    return service.siweLink(
      USER_ID,
      publicKey,
      message,
      signature,
      proof.challenge,
      proof.challengeSignature
    );
  }

  it('links a wallet once the account identity key is re-proved', async () => {
    await linkWith(SIWE_LINK_STATEMENT, true);
    expect(await authMethods.count({ where: { userId: USER_ID, kind: 'wallet' } })).toBe(1);
  });

  it('refuses a link carrying no valid identity re-proof, and links nothing', async () => {
    await expect(linkWith(SIWE_LINK_STATEMENT, false)).rejects.toThrow(UnauthorizedException);
    expect(await authMethods.count({ where: { userId: USER_ID } })).toBe(0);
  });

  it('refuses a phished sign-in signature replayed as a link, and links nothing', async () => {
    await expect(linkWith(SIWE_LOGIN_STATEMENT, true)).rejects.toThrow(UnauthorizedException);
    expect(await authMethods.count({ where: { userId: USER_ID } })).toBe(0);
  });
});
