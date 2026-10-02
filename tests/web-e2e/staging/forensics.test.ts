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
