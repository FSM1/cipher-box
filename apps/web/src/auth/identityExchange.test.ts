import { afterEach, describe, expect, it, vi } from 'vitest';
import { createIdentityExchange, isIdentityMethod } from './identityExchange';

const BASE = 'https://api.example.test';

const GRANT = { token: 'header.payload.signature', verifierId: 'subject-42', email: null };

function stubFetch(response: Response | (() => Promise<Response>)) {
  const fetchMock = vi.fn(
    typeof response === 'function' ? response : () => Promise.resolve(response)
  );
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** The one call each request made, as URL plus parsed body. */
function requestOf(fetchMock: ReturnType<typeof vi.fn>) {
  const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
  return { url, body: JSON.parse(init.body as string) as Record<string, unknown> };
}

afterEach(() => vi.unstubAllGlobals());

describe('the identity exchange', () => {
  it('posts a Google credential and reads back the minted grant', async () => {
    const fetchMock = stubFetch(jsonResponse({ ...GRANT, email: 'member@example.test' }));

    const credential = await createIdentityExchange(BASE).fromGoogleToken('google.id.token');

    expect(requestOf(fetchMock)).toEqual({
      url: `${BASE}/auth/identity/google`,
      body: { idToken: 'google.id.token' },
    });
    expect(credential).toEqual({
      method: 'google',
      token: 'header.payload.signature',
      verifierId: 'subject-42',
      email: 'member@example.test',
    });
  });

  it('posts an email code and marks the grant as the email method', async () => {
    const fetchMock = stubFetch(jsonResponse({ ...GRANT, email: 'member@example.test' }));

    const credential = await createIdentityExchange(BASE).fromEmailCode(
      'member@example.test',
      '123456'
    );

    expect(requestOf(fetchMock)).toEqual({
      url: `${BASE}/auth/identity/email/verify-code`,
      body: { email: 'member@example.test', code: '123456' },
    });
    expect(credential.method).toBe('email');
  });

  it('posts a wallet signature and marks the grant as the wallet method', async () => {
    const fetchMock = stubFetch(jsonResponse(GRANT));

    const credential = await createIdentityExchange(BASE).fromWalletSignature(
      'siwe-message',
      '0xab'
    );

    expect(requestOf(fetchMock)).toEqual({
      url: `${BASE}/auth/identity/wallet`,
      body: { message: 'siwe-message', signature: '0xab' },
    });
    expect(credential).toMatchObject({ method: 'wallet', email: null });
  });

  it('reads the SIWE nonce from the API, which the engine cannot answer pre-start', async () => {
    const fetchMock = stubFetch(jsonResponse({ nonce: 'nonce123456789ab' }));

    await expect(createIdentityExchange(BASE).walletNonce()).resolves.toBe('nonce123456789ab');
    expect(requestOf(fetchMock).url).toBe(`${BASE}/auth/siwe/challenge`);
  });

  it('does not double the slash when the configured origin carries one', async () => {
    const fetchMock = stubFetch(jsonResponse({ success: true }));

    await createIdentityExchange(`${BASE}/`).sendEmailCode('member@example.test');

    expect(requestOf(fetchMock).url).toBe(`${BASE}/auth/identity/email/send-code`);
  });

  it("surfaces the API's own refusal, which is written for the member", async () => {
    stubFetch(jsonResponse({ message: 'The verification code has expired' }, 401));

    await expect(
      createIdentityExchange(BASE).fromEmailCode('member@example.test', '123456')
    ).rejects.toThrow('The verification code has expired');
  });

  it('surfaces the first message when validation refuses with a list', async () => {
    stubFetch(jsonResponse({ message: ['email must be an email address'] }, 400));

    await expect(createIdentityExchange(BASE).sendEmailCode('nope')).rejects.toThrow(
      'email must be an email address'
    );
  });

  it('reports a bare refusal when something other than the API answered', async () => {
    stubFetch(new Response('<html>502</html>', { status: 502 }));

    await expect(createIdentityExchange(BASE).sendEmailCode('member@example.test')).rejects.toThrow(
      /sign-in failed \(502\)/
    );
  });

  it('reports an unreachable API as a connection problem, not a refusal', async () => {
    stubFetch(() => Promise.reject(new Error('NetworkError')));

    await expect(createIdentityExchange(BASE).sendEmailCode('member@example.test')).rejects.toThrow(
      /could not be reached/
    );
  });
});

describe('isIdentityMethod', () => {
  it('admits exactly the three methods', () => {
    expect(['google', 'email', 'wallet'].every(isIdentityMethod)).toBe(true);
    expect(isIdentityMethod('jwt')).toBe(false);
    expect(isIdentityMethod(undefined)).toBe(false);
  });
});
