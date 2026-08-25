// @vitest-environment node
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  CADDY_SNIPPET_FILE,
  CONTENT_SECURITY_POLICY,
  DEV_CONTENT_SECURITY_POLICY,
  DEV_SECURITY_HEADERS,
  SERVED_SECURITY_HEADERS,
  caddySecurityHeaders,
} from './csp';

const repoFile = (path: string) => fileURLToPath(new URL(`../../../${path}`, import.meta.url));

const read = (path: string) => readFileSync(repoFile(path), 'utf8');

/**
 * The Caddyfile blocks that serve the built app. Matched on what a block serves
 * rather than on a hostname, so a renamed or added vhost is covered rather than
 * silently skipped.
 */
function appVhosts(): string[] {
  return read('docker/Caddyfile')
    .split(/^\}$/m)
    .filter((block) => block.includes('root * /srv/web'));
}

describe('the served policy', () => {
  it('lets no page frame the app', () => {
    expect(CONTENT_SECURITY_POLICY).toContain("frame-ancestors 'none'");
  });

  it('runs no inline script', () => {
    expect(CONTENT_SECURITY_POLICY).not.toContain("'unsafe-inline'");
  });
});

describe('the dev policy', () => {
  it('widens nothing but the inline script the refresh preamble needs', () => {
    expect(DEV_CONTENT_SECURITY_POLICY.replace(" 'unsafe-inline'", '')).toBe(
      CONTENT_SECURITY_POLICY
    );
  });

  it('keeps every other served header at its served value', () => {
    for (const [name, value] of Object.entries(SERVED_SECURITY_HEADERS)) {
      if (name === 'Content-Security-Policy') continue;
      expect(DEV_SECURITY_HEADERS[name]).toBe(value);
    }
  });
});

describe('the deployed headers', () => {
  it('are the generated snippet, not a hand-kept copy', () => {
    expect(read(`docker/${CADDY_SNIPPET_FILE}`)).toBe(caddySecurityHeaders());
  });

  it('reach every vhost serving the app, and only through the snippet', () => {
    const vhosts = appVhosts();
    expect(vhosts.length).toBeGreaterThan(0);

    for (const vhost of vhosts) {
      expect(vhost).toContain(`import /etc/caddy/${CADDY_SNIPPET_FILE}`);
      for (const name of Object.keys(SERVED_SECURITY_HEADERS)) expect(vhost).not.toContain(name);
    }
  });

  it('are shipped to the host the vhost imports them on', () => {
    expect(read('docker/docker-compose.staging.yml')).toContain(
      `./${CADDY_SNIPPET_FILE}:/etc/caddy/${CADDY_SNIPPET_FILE}`
    );
    expect(read('.github/workflows/deploy-staging.yml')).toContain(`docker/${CADDY_SNIPPET_FILE}`);
  });
});
