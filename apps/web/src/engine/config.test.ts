import { describe, expect, it } from 'vitest';
import { engineHostConfig, environment } from './config';

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

describe('environment', () => {
  it('names the deployment, defaulting an absent value to local', () => {
    expect(environment({ VITE_ENVIRONMENT: 'staging' })).toBe('staging');
    expect(environment({ VITE_ENVIRONMENT: '' })).toBe('local');
    expect(environment({})).toBe('local');
  });

  it('rejects an unrecognized deployment rather than silently defaulting it', () => {
    // A typo would otherwise pick the wrong Web3Auth network, deriving a
    // different identity over an empty vault.
    expect(() => environment({ VITE_ENVIRONMENT: 'producton' })).toThrow(/VITE_ENVIRONMENT/);
  });
});
