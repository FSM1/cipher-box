import { describe, expect, it } from 'vitest';
import { DEFAULT_WEB_PORT, webPort } from './options';

describe('webPort', () => {
  it('serves a default when the environment names none', () => {
    expect(webPort(undefined)).toBe(DEFAULT_WEB_PORT);
    expect(webPort('')).toBe(DEFAULT_WEB_PORT);
  });

  it('takes a port the environment names', () => {
    expect(webPort('4180')).toBe(4180);
  });

  it('refuses a value that is not a port', () => {
    expect(() => webPort('4180x')).toThrow(/not a number/);
    expect(() => webPort('-1')).toThrow(/not a number/);
    expect(() => webPort('0')).toThrow(/outside/);
    expect(() => webPort('65536')).toThrow(/outside/);
  });
});
