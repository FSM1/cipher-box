// @vitest-environment node
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { CONTENT_SECURITY_POLICY, DEV_CONTENT_SECURITY_POLICY } from './csp';

const CADDYFILE = fileURLToPath(new URL('../../../docker/Caddyfile', import.meta.url));

/** The policy the staging web vhost serves, as its site block declares it. */
function stagingPolicy(): string {
  const caddyfile = readFileSync(CADDYFILE, 'utf8');
  const app = caddyfile.slice(caddyfile.indexOf('app-staging.cipherbox.cc {'));
  const declared = /Content-Security-Policy\s+"([^"]+)"/.exec(app);
  if (declared === null) throw new Error('the staging web vhost declares no policy');
  return declared[1];
}

describe('the served policy', () => {
  it('lets no page frame the app', () => {
    expect(CONTENT_SECURITY_POLICY).toContain("frame-ancestors 'none'");
  });

  it('keeps the engine worker and its WASM loadable', () => {
    expect(CONTENT_SECURITY_POLICY).toContain("'wasm-unsafe-eval'");
    expect(CONTENT_SECURITY_POLICY).toContain("worker-src 'self' blob:");
  });

  it('is the one staging serves', () => {
    expect(stagingPolicy()).toBe(CONTENT_SECURITY_POLICY);
  });
});

describe('the dev policy', () => {
  it('refuses framing exactly as the served one does', () => {
    expect(DEV_CONTENT_SECURITY_POLICY).toContain("frame-ancestors 'none'");
  });

  it('widens nothing but the inline script the refresh preamble needs', () => {
    expect(DEV_CONTENT_SECURITY_POLICY.replace(" 'unsafe-inline'", '')).toBe(
      CONTENT_SECURITY_POLICY
    );
  });
});
