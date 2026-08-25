// @vitest-environment node
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { CADDY_SECURITY_HEADERS, DEV_SECURITY_HEADERS, SERVED_SECURITY_HEADERS } from './csp';

const read = (path: string) =>
  readFileSync(fileURLToPath(new URL(`../../../${path}`, import.meta.url)), 'utf8');

const SERVED_POLICY = SERVED_SECURITY_HEADERS['Content-Security-Policy'];

/**
 * The Caddyfile blocks that serve the built app, comments stripped. Matched on
 * what a block serves rather than on a hostname, so a renamed or added vhost is
 * covered rather than silently skipped.
 */
function appVhosts(): string[] {
  return read('docker/Caddyfile')
    .split(/^\}$/m)
    .filter((block) => block.includes('root * /srv/web'))
    .map((block) =>
      block
        .split('\n')
        .filter((line) => !line.trim().startsWith('#'))
        .join('\n')
    );
}

describe('the served policy', () => {
  it('lets no page frame the app', () => {
    expect(SERVED_POLICY).toContain("frame-ancestors 'none'");
  });

  it('runs no inline script', () => {
    expect(SERVED_POLICY).not.toContain("'unsafe-inline'");
  });
});

describe('the dev policy', () => {
  it('widens nothing but the inline script the refresh preamble needs', () => {
    expect(DEV_SECURITY_HEADERS['Content-Security-Policy'].replace(" 'unsafe-inline'", '')).toBe(
      SERVED_POLICY
    );
  });
});

describe('the deployed headers', () => {
  it('are the generated snippet, not a hand-kept copy', () => {
    expect(read('docker/csp.caddy')).toBe(CADDY_SECURITY_HEADERS);
  });

  it('reach every vhost serving the app, and only through the snippet', () => {
    const vhosts = appVhosts();
    expect(vhosts.length).toBeGreaterThan(0);

    for (const vhost of vhosts) {
      expect(vhost).toContain('import /etc/caddy/csp.caddy');
      for (const name of Object.keys(SERVED_SECURITY_HEADERS)) expect(vhost).not.toContain(name);
    }
  });
});
