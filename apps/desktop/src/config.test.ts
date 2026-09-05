import { describe, expect, it } from 'vitest';
import { DEFAULT_API_URL, desktopConfig } from './config';

const BUILD = {
  VITE_WEB3AUTH_CLIENT_ID: 'a-client',
  VITE_WEB3AUTH_VERIFIER: 'a-verifier',
};

const resolved = (apiUrl?: string): string =>
  desktopConfig(apiUrl === undefined ? BUILD : { ...BUILD, VITE_API_URL: apiUrl }).apiBaseUrl;

/**
 * The shell mints its identity token at this origin and the engine carries the
 * session bearer to it, so the scheme is a trust boundary rather than a taste.
 */
describe('the API origin the shell resolves', () => {
  it('takes an https origin', () => {
    expect(resolved('https://api.example.com')).toBe('https://api.example.com');
  });

  it('takes cleartext on the loopback the local and CI stacks run on', () => {
    expect(resolved('http://localhost:3000')).toBe('http://localhost:3000');
    expect(resolved('http://127.0.0.1:8080')).toBe('http://127.0.0.1:8080');
  });

  it('falls back to an origin that holds to the rule', () => {
    expect(resolved()).toBe(DEFAULT_API_URL);
    expect(resolved('   ')).toBe(DEFAULT_API_URL);
  });

  it('refuses cleartext to any other host', () => {
    expect(() => resolved('http://api.example.com')).toThrow(/https:/);
    // A name that merely ends in the loopback one is a different host.
    expect(() => resolved('http://localhost.example.com')).toThrow(/https:/);
  });

  it('refuses a scheme that is neither', () => {
    expect(() => resolved('ftp://api.example.com')).toThrow(/https:/);
    expect(() => resolved('file:///etc/hosts')).toThrow(/https:/);
  });

  it('refuses a value that is not a URL at all', () => {
    expect(() => resolved('api.example.com')).toThrow(/not a URL/);
  });
});
