import { describe, expect, it } from 'vitest';
import { engineHostConfig, environment, missingDeployEnv } from './config';

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

  it('reads a blank API origin as unconfigured rather than as a base URL', () => {
    // `VITE_API_URL=` reads as `''`, which `new URL` rejects outright.
    expect(engineHostConfig({ VITE_API_URL: '' }, artifact).apiBaseUrl).toBe(
      'http://localhost:3000'
    );
  });

  it('carries the read accelerator and the public gateway fallbacks through', () => {
    const config = engineHostConfig(
      {
        VITE_READ_ACCELERATOR_URL: 'https://accelerator.example.test',
        VITE_PUBLIC_GATEWAYS: ' https://a.example.test , https://b.example.test ',
      },
      artifact
    );
    expect(config.acceleratorBaseUrl).toBe('https://accelerator.example.test');
    expect(config.publicGateways).toEqual(['https://a.example.test', 'https://b.example.test']);
  });

  it('leaves the content gateway unset rather than defaulting it', () => {
    // No endpoint nobody chose: an unconfigured build reads nothing, which the
    // engine surfaces as unavailable rather than trusting a stand-in.
    const config = engineHostConfig({}, artifact);
    expect(config.acceleratorBaseUrl).toBeUndefined();
    expect(config.publicGateways).toBeUndefined();
    expect(
      engineHostConfig({ VITE_PUBLIC_GATEWAYS: ' , ' }, artifact).publicGateways
    ).toBeUndefined();
  });
});

describe('missingDeployEnv', () => {
  it('names the login variables a deployed build is missing', () => {
    expect(missingDeployEnv({ VITE_ENVIRONMENT: 'staging' })).toEqual([
      'VITE_WEB3AUTH_CLIENT_ID',
      'VITE_WEB3AUTH_VERIFIER',
    ]);
    // A variable substituted as blank is as unusable as an absent one.
    expect(
      missingDeployEnv({
        VITE_ENVIRONMENT: 'production',
        VITE_WEB3AUTH_CLIENT_ID: 'client',
        VITE_WEB3AUTH_VERIFIER: '',
      })
    ).toEqual(['VITE_WEB3AUTH_VERIFIER']);
  });

  it('passes a fully configured deployment', () => {
    expect(
      missingDeployEnv({
        VITE_ENVIRONMENT: 'staging',
        VITE_WEB3AUTH_CLIENT_ID: 'client',
        VITE_WEB3AUTH_VERIFIER: 'verifier',
      })
    ).toEqual([]);
  });

  it('exempts builds that name no deployment', () => {
    expect(missingDeployEnv({})).toEqual([]);
    expect(missingDeployEnv({ VITE_ENVIRONMENT: 'ci' })).toEqual([]);
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
