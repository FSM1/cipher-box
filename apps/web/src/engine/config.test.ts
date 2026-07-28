import { describe, expect, it } from 'vitest';
import { engineBootstrapConfig } from './config';

describe('engineBootstrapConfig', () => {
  it('derives the mailbox URL from the API origin', () => {
    const config = engineBootstrapConfig({ VITE_API_URL: 'https://api.example.test/' });
    expect(config.mailboxUrl).toBe('https://api.example.test/mailbox');
  });

  it('splits the routing endpoint set and strips trailing slashes', () => {
    const config = engineBootstrapConfig({
      VITE_ROUTING_ENDPOINTS: ' https://someguy.example.test/ , https://public.example.test ',
    });
    expect(config.recordEndpoints).toEqual([
      'https://someguy.example.test',
      'https://public.example.test',
    ]);
  });

  it('rejects an empty routing endpoint set rather than building an unroutable engine', () => {
    expect(() => engineBootstrapConfig({ VITE_ROUTING_ENDPOINTS: ' , ' })).toThrow(
      /empty endpoint set/
    );
  });

  it('points the worker at the wasm artifact URLs it is given', () => {
    const config = engineBootstrapConfig({
      VITE_WASM_MODULE_URL: '/assets/engine.js',
      VITE_WASM_BINARY_URL: '/assets/engine.wasm',
    });
    expect(config.wasmModuleUrl).toBe('/assets/engine.js');
    expect(config.wasmBinaryUrl).toBe('/assets/engine.wasm');
  });
});
