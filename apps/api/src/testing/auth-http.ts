import request, { type Response } from 'supertest';
import type { privateKeyToAccount } from 'viem/accounts';
import { createSiweMessage } from 'viem/siwe';
import type { StepUpOperation } from '../auth/services/challenge.service';
import { SIWE_LINK_STATEMENT } from '../auth/services/siwe.service';
import type { HttpIntegrationApp } from './http-integration-app';
import { newIdentity, signChallenge, type TestIdentity } from './identities';

/** The HTTP server a suite drives. */
type Http = HttpIntegrationApp['http'];

type Wallet = ReturnType<typeof privateKeyToAccount>;

export function jwtPayload(token: string): { sub: string; publicKey: string } {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
}

/**
 * A challenge-signature login; the first one creates the account. An
 * `identityToken` binds its subject to an unbound account (ADR 0058 D2).
 */
export async function identityLogin(
  http: Http,
  identity: TestIdentity = newIdentity(),
  identityToken?: string
): Promise<{ identity: TestIdentity; loginRes: Response; accessToken: string }> {
  const issued = await request(http)
    .post('/auth/challenge')
    .send({ publicKey: identity.publicKey })
    .expect(200);
  const loginRes = await request(http)
    .post('/auth/login')
    .send({
      publicKey: identity.publicKey,
      challenge: issued.body.challenge,
      signature: signChallenge(issued.body.challenge, identity.privateKey),
      ...(identityToken === undefined ? {} : { identityToken }),
    })
    .expect(200);
  return { identity, loginRes, accessToken: loginRes.body.accessToken as string };
}

/** The account key's answer to a fresh step-up challenge, as link and unlink demand. */
export async function identityReproof(
  http: Http,
  identity: TestIdentity,
  accessToken: string,
  operation: StepUpOperation = 'link',
  methodId?: string
): Promise<{ challenge: string; challengeSignature: string }> {
  const res = await request(http)
    .post('/auth/challenge/step-up')
    .set('Authorization', `Bearer ${accessToken}`)
    .send(methodId === undefined ? { operation } : { operation, methodId })
    .expect(200);
  const challenge = res.body.challenge as string;
  return { challenge, challengeSignature: signChallenge(challenge, identity.privateKey) };
}

/**
 * A nonce from the pool the intent names: the sign-in pool is unauthenticated,
 * the link pool is owner-authenticated and serves no other route.
 */
export async function siweNonce(http: Http, linkAccessToken?: string): Promise<string> {
  const pending = linkAccessToken
    ? request(http)
        .post('/auth/siwe/link-challenge')
        .set('Authorization', `Bearer ${linkAccessToken}`)
    : request(http).post('/auth/siwe/challenge');
  return (await pending.send({}).expect(200)).body.nonce;
}

export async function siweSign(
  http: Http,
  wallet: Wallet,
  statement: string,
  signer: Wallet = wallet,
  linkAccessToken?: string
): Promise<{ message: string; signature: string }> {
  const message = createSiweMessage({
    address: wallet.address,
    chainId: 1,
    domain: 'localhost:5173',
    nonce: await siweNonce(http, linkAccessToken),
    uri: 'http://localhost:5173',
    version: '1',
    statement,
  });
  return { message, signature: await signer.signMessage({ message }) };
}

/** A complete `/auth/siwe/link` body: the SIWE pair plus the identity re-proof. */
export async function siweLinkBody(
  http: Http,
  identity: TestIdentity,
  accessToken: string,
  wallet: Wallet,
  statement: string = SIWE_LINK_STATEMENT
) {
  const [siwe, reproof] = await Promise.all([
    siweSign(http, wallet, statement, wallet, accessToken),
    identityReproof(http, identity, accessToken),
  ]);
  return { ...siwe, ...reproof };
}

export function link(http: Http, accessToken: string, body: Record<string, string>) {
  return request(http)
    .post('/auth/siwe/link')
    .set('Authorization', `Bearer ${accessToken}`)
    .send(body);
}
