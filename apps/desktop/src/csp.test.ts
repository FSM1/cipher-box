import { describe, expect, it } from 'vitest';
import { contentSecurityPolicy, DEFAULT_API_URL as CSP_DEFAULT_API_URL } from '../scripts/csp.mjs';
import { DEFAULT_API_URL, desktopConfig } from './config';
import tauriConf from '../src-tauri/tauri.conf.json';

const BUILD = {
  VITE_WEB3AUTH_CLIENT_ID: 'a-client',
  VITE_WEB3AUTH_VERIFIER: 'a-verifier',
};

function connectSrc(csp: string): string {
  const directive = csp.split('; ').find((entry) => entry.startsWith('connect-src '));
  if (directive === undefined) throw new Error('the policy names no connect-src');
  return directive;
}

describe('the shell content security policy', () => {
  it('allows the API origin the app resolves, when one is configured', () => {
    const env = { ...BUILD, VITE_API_URL: 'https://api.example.com/v2/' };
    expect(connectSrc(contentSecurityPolicy(env))).toContain(
      new URL(desktopConfig(env).apiBaseUrl).origin
    );
  });

  it('allows the API origin the app falls back to, when none is', () => {
    expect(CSP_DEFAULT_API_URL).toBe(DEFAULT_API_URL);
    expect(connectSrc(contentSecurityPolicy(BUILD))).toContain(
      new URL(desktopConfig(BUILD).apiBaseUrl).origin
    );
  });

  it('allows the Core Kit its own hosts and Tauri its IPC', () => {
    const connect = connectSrc(contentSecurityPolicy(BUILD));
    expect(connect).toContain('https://*.web3auth.io');
    expect(connect).toContain('https://*.tor.us');
    expect(connect).toContain('ipc:');
  });

  it('does not reach Google, which is opened natively instead', () => {
    expect(contentSecurityPolicy(BUILD)).not.toContain('google');
  });

  it('keeps everything the login does not need shut', () => {
    const csp = contentSecurityPolicy(BUILD);
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-src 'none'");
    expect(csp).toContain("form-action 'none'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain("'unsafe-eval'");
  });

  it('refuses to build a policy for an API URL that is not one', () => {
    expect(() => contentSecurityPolicy({ ...BUILD, VITE_API_URL: 'not a url' })).toThrow();
  });
});

/**
 * A build that does not go through `scripts/tauri.mjs` still gets a policy that
 * admits the IPC endpoint, because `invoke` otherwise falls back to
 * `postMessage` and the login secret crosses as a JSON number array.
 */
describe('the committed shell policy', () => {
  const csp = tauriConf.app.security.csp;

  it('admits the Tauri IPC endpoint the raw-bytes secret transport needs', () => {
    expect(connectSrc(csp)).toContain('ipc:');
    expect(connectSrc(csp)).toContain('http://ipc.localhost');
  });

  it('admits nothing else', () => {
    expect(csp).toContain("default-src 'self'");
    expect(connectSrc(csp)).toBe("connect-src 'self' ipc: http://ipc.localhost");
  });
});
