import { describe, expect, it } from 'vitest';
import { engineHostConfig } from './config';

describe('engineHostConfig', () => {
  it('splits the routing endpoint set on commas', () => {
    const config = engineHostConfig({
      VITE_ROUTING_ENDPOINTS: ' https://someguy.example.test , https://public.example.test ',
    });
    expect(config.recordEndpoints).toEqual([
      'https://someguy.example.test',
      'https://public.example.test',
    ]);
  });

  it('carries the API origin and the wasm artifact URLs through', () => {
    const config = engineHostConfig({
      VITE_API_URL: 'https://api.example.test',
      VITE_WASM_MODULE_URL: '/assets/engine.js',
      VITE_WASM_BINARY_URL: '/assets/engine.wasm',
    });
    expect(config.apiBaseUrl).toBe('https://api.example.test');
    expect(config.wasmModuleUrl).toBe('/assets/engine.js');
    expect(config.wasmBinaryUrl).toBe('/assets/engine.wasm');
  });

  it('rejects a routing endpoint set that parses to nothing', () => {
    expect(() => engineHostConfig({ VITE_ROUTING_ENDPOINTS: ' , ' })).toThrow(
      /VITE_ROUTING_ENDPOINTS/
    );
  });

  it('falls back to defaults for an unconfigured environment', () => {
    const config = engineHostConfig({});
    expect(config.apiBaseUrl).toBe('http://localhost:3000');
    expect(config.recordEndpoints).toEqual(['https://delegated-ipfs.dev']);
  });
});
