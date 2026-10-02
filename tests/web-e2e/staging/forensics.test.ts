import { describe, expect, it } from 'vitest';
import { redact, requestTarget } from './forensics';

describe('redact', () => {
  it('removes a JWT', () => {
    const jwt = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl';
    expect(redact(`refresh failed for ${jwt} now`)).toBe('refresh failed for [redacted] now');
  });

  it('removes long hex and base64 runs', () => {
    const hex = `0x${'ab'.repeat(32)}`;
    const base64 = `${'QUJD'.repeat(10)}==`;
    expect(redact(`key ${hex} share ${base64}`)).toBe('key [redacted] share [redacted]');
  });

  it('removes a 30-digit hex secret', () => {
    expect(redact(`seed ${'c0ffee'.repeat(5)} end`)).toBe('seed [redacted] end');
  });

  it('removes padded base64 that holds a slash', () => {
    expect(redact(`blob ${'ab+/'.repeat(8)}== end`)).toBe('blob [redacted] end');
  });

  it('removes a query and a fragment from a url in free text', () => {
    expect(redact('GET https://app.example.com/cb?code=abc&state=xyz failed')).toBe(
      'GET https://app.example.com/cb[redacted] failed'
    );
    expect(redact('open https://app.example.com/s#k=secret now')).toBe(
      'open https://app.example.com/s[redacted] now'
    );
  });

  it('removes an email', () => {
    expect(redact('code sent to some.one+e2e@mail.example.co.uk today')).toBe(
      'code sent to [redacted] today'
    );
  });

  it('redacts a long path segment and keeps the rest of the path', () => {
    const ipnsName = 'k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8';
    expect(redact(`response 404 gw.example.com/routing/v1/ipns/${ipnsName}`)).toBe(
      'response 404 gw.example.com/routing/v1/ipns/[redacted]'
    );
  });

  it('keeps ordinary text, hosts and short ids', () => {
    const line = 'response 503 node-1.dev-node.web3auth.io/sss/jrpc: Cannot perform rss round 1';
    expect(redact(line)).toBe(line);
  });
});

describe('requestTarget', () => {
  it('keeps the host and the path, not the query', () => {
    expect(requestTarget('https://api.example.com/auth/refresh?token=abc')).toBe(
      'api.example.com/auth/refresh'
    );
  });
});
