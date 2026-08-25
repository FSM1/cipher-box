// @vitest-environment node
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { CONTENT_SECURITY_POLICY, DEV_CONTENT_SECURITY_POLICY } from './csp';

const CADDYFILE = fileURLToPath(new URL('../../../docker/Caddyfile', import.meta.url));

/**
 * The policy each deployed vhost serving the built app declares. Matched on what
 * a block serves rather than on a hostname, so a renamed or added vhost is
 * covered rather than silently skipped, and a vhost declaring the header more
 * than once fails rather than being read as its first declaration.
 */
function deployedPolicies(): string[] {
  const blocks = readFileSync(CADDYFILE, 'utf8').split(/^\}$/m);
  return blocks
    .filter((block) => block.includes('root * /srv/web'))
    .map((block) => {
      const declared = [...block.matchAll(/Content-Security-Policy\s+"([^"]+)"/g)];
      if (declared.length !== 1 || block.includes('-Content-Security-Policy')) {
        throw new Error(`a vhost serving the app declares ${declared.length} policies`);
      }
      return declared[0][1];
    });
}

describe('the served policy', () => {
  it('lets no page frame the app', () => {
    expect(CONTENT_SECURITY_POLICY).toContain("frame-ancestors 'none'");
  });

  it('runs no inline script', () => {
    expect(CONTENT_SECURITY_POLICY).not.toContain("'unsafe-inline'");
  });

  it('is the one every deployed vhost serves', () => {
    const deployed = deployedPolicies();

    expect(deployed.length).toBeGreaterThan(0);
    for (const policy of deployed) expect(policy).toBe(CONTENT_SECURITY_POLICY);
  });
});

describe('the dev policy', () => {
  it('widens nothing but the inline script the refresh preamble needs', () => {
    expect(DEV_CONTENT_SECURITY_POLICY.replace(" 'unsafe-inline'", '')).toBe(
      CONTENT_SECURITY_POLICY
    );
  });
});
