import { describe, expect, it } from 'vitest';
import './polyfills';

describe('the shell globals', () => {
  it('supplies what the Core Kit reads off the global scope', () => {
    expect(typeof globalThis.process).toBe('object');
    expect(typeof globalThis.Buffer).toBe('function');
  });

  it.each(['localStorage', 'sessionStorage', 'indexedDB'])(
    'refuses %s, which the webview would persist to the app data dir',
    (store) => {
      expect(() => (globalThis as Record<string, unknown>)[store]).toThrow();
    }
  );
});
