import { describe, expect, it } from 'vitest';

import { STREAM_PATH_PREFIX, ticketFromPath } from './protocol.js';
import { StreamRegistry, type MediaSource } from './registry.js';

const ORIGIN = 'https://vault.example';

const source = (byte: number): MediaSource => ({
  node: new Uint8Array([byte, byte, byte]),
  mimeType: 'video/mp4',
});

const ticketOf = (url: string): string => {
  const ticket = ticketFromPath(url);
  if (ticket === null) throw new Error(`not a stream url: ${url}`);
  return ticket;
};

describe('StreamRegistry', () => {
  it('resolves a registered ticket back to its source', () => {
    const registry = new StreamRegistry(ORIGIN);
    const media = source(7);

    const url = registry.register(media);

    expect(url.startsWith(STREAM_PATH_PREFIX)).toBe(true);
    expect(registry.lookup(ticketOf(url))).toBe(media);
  });

  it('stops resolving a revoked url', () => {
    const registry = new StreamRegistry(ORIGIN);
    const url = registry.register(source(1));

    expect(registry.revoke(url)).toBe(true);

    expect(registry.lookup(ticketOf(url))).toBeUndefined();
  });

  it('revokes the absolute url a media element reads back off its src', () => {
    const registry = new StreamRegistry(ORIGIN);
    const url = registry.register(source(1));

    expect(registry.revoke(`${ORIGIN}${url}`)).toBe(true);

    expect(registry.lookup(ticketOf(url))).toBeUndefined();
  });

  it('revokes a url carrying a media fragment', () => {
    const registry = new StreamRegistry(ORIGIN);
    const url = registry.register(source(1));

    expect(registry.revoke(`${ORIGIN}${url}#t=10`)).toBe(true);

    expect(registry.lookup(ticketOf(url))).toBeUndefined();
  });

  it('refuses a url naming another origin', () => {
    const registry = new StreamRegistry(ORIGIN);
    const url = registry.register(source(1));

    expect(registry.revoke(`https://evil.example${url}`)).toBe(false);

    expect(registry.lookup(ticketOf(url))).toBeDefined();
  });

  it('reports a revoke for a url it never minted', () => {
    const registry = new StreamRegistry(ORIGIN);
    const url = registry.register(source(1));

    expect(registry.revoke('/elsewhere/abc')).toBe(false);
    expect(registry.revoke(`${ORIGIN}/stream/no-such-ticket`)).toBe(false);

    expect(registry.lookup(ticketOf(url))).toBeDefined();
  });

  it('mints a distinct random ticket per registration, never derived from the node', () => {
    const registry = new StreamRegistry(ORIGIN);
    const media = source(9);

    const first = ticketOf(registry.register(media));
    const second = ticketOf(registry.register(media));

    // Identical sources minting distinct random tickets is what makes a ticket
    // unguessable from the content it names.
    expect(first).not.toBe(second);
    expect(first).toMatch(/^[0-9a-f-]{36}$/);
    expect(second).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('drops every ticket on clear', () => {
    const registry = new StreamRegistry(ORIGIN);
    const a = ticketOf(registry.register(source(1)));
    const b = ticketOf(registry.register(source(2)));

    registry.clear();

    expect(registry.lookup(a)).toBeUndefined();
    expect(registry.lookup(b)).toBeUndefined();
  });

  it('mints through the injected ticket source', () => {
    let n = 0;
    const registry = new StreamRegistry(ORIGIN, () => `t${(n += 1)}`);

    expect(registry.register(source(1))).toBe(`${STREAM_PATH_PREFIX}t1`);
    expect(registry.register(source(2))).toBe(`${STREAM_PATH_PREFIX}t2`);
  });

  it('refuses to mint a ticket it already holds', () => {
    const registry = new StreamRegistry(ORIGIN, () => 'fixed');
    registry.register(source(1));

    // Reuse would serve the first file's pinned stream under the second's head.
    expect(() => registry.register(source(2))).toThrow(/minted once/);
  });
});
