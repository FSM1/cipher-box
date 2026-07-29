import { describe, expect, it } from 'vitest';
import { engineHostConfig } from './config';

const artifact = {
  wasmModuleUrl: '/assets/cipherbox_wasm-deadbeef.js',
  wasmBinaryUrl: '/assets/cipherbox_wasm_bg-deadbeef.wasm',
};

describe('engineHostConfig', () => {
  it('splits the routing endpoint set on commas', () => {
    const config = engineHostConfig(
      {
        VITE_ROUTING_ENDPOINTS: ' https://someguy.example.test , https://public.example.test ',
      },
      artifact
    );
    expect(config.recordEndpoints).toEqual([
      'https://someguy.example.test',
      'https://public.example.test',
    ]);
  });

  it('carries the API origin and the bundler-resolved artifact URLs through', () => {
    const config = engineHostConfig({ VITE_API_URL: 'https://api.example.test' }, artifact);
    expect(config.apiBaseUrl).toBe('https://api.example.test');
    expect(config.wasmModuleUrl).toBe(artifact.wasmModuleUrl);
    expect(config.wasmBinaryUrl).toBe(artifact.wasmBinaryUrl);
  });

  it('rejects a routing endpoint set that parses to nothing', () => {
    expect(() => engineHostConfig({ VITE_ROUTING_ENDPOINTS: ' , ' }, artifact)).toThrow(
      /VITE_ROUTING_ENDPOINTS/
    );
  });

  it('falls back to defaults for an unconfigured environment', () => {
    const config = engineHostConfig({}, artifact);
    expect(config.apiBaseUrl).toBe('http://localhost:3000');
    expect(config.recordEndpoints).toEqual(['https://delegated-ipfs.dev']);
  });
});
