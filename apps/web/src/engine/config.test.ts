import { describe, expect, it } from 'vitest';
import { engineHostConfig, environment, loginEnv, missingDeployEnv, shipsE2eHook } from './config';

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
    const config = engineHostConfig({}, artifact);
    expect(config.acceleratorBaseUrl).toBeUndefined();
    expect(config.publicGateways).toEqual([]);
    expect(engineHostConfig({ VITE_PUBLIC_GATEWAYS: ' , ' }, artifact).publicGateways).toEqual([]);
    for (const unset of ['', '   ']) {
      // Whitespace would configure a gateway source with an unusable base URL —
      // reads then fail per-request instead of staying dormant.
      expect(
        engineHostConfig({ VITE_READ_ACCELERATOR_URL: unset }, artifact).acceleratorBaseUrl
      ).toBeUndefined();
    }
  });

  it('trims a configured API origin, which is concatenated into request URLs', () => {
    expect(
      engineHostConfig({ VITE_API_URL: ' https://api.example.test\n' }, artifact).apiBaseUrl
    ).toBe('https://api.example.test');
  });

  it('never defaults a whitespace API origin to localhost', () => {
    // Defaulting here would point a misconfigured deployment at whatever answers
    // on the user's machine; the engine's own edge check refuses a blank base.
    expect(engineHostConfig({ VITE_API_URL: '   ' }, artifact).apiBaseUrl).toBe('');
  });
});

describe('missingDeployEnv', () => {
  const deployed = {
    VITE_ENVIRONMENT: 'staging',
    VITE_WEB3AUTH_CLIENT_ID: 'client',
    VITE_WEB3AUTH_VERIFIER: 'verifier',
    VITE_GOOGLE_CLIENT_ID: 'google-client',
    VITE_API_URL: 'https://api.example.test',
  };

  it('names the variables a deployed build is missing', () => {
    expect(missingDeployEnv({ VITE_ENVIRONMENT: 'staging' })).toEqual([
      'VITE_WEB3AUTH_CLIENT_ID',
      'VITE_WEB3AUTH_VERIFIER',
      'VITE_GOOGLE_CLIENT_ID',
      'VITE_API_URL',
    ]);
    // A variable substituted as blank is as unusable as an absent one, and a
    // whitespace-only one is blank — a repo variable set to a stray space or
    // newline must not sail through the gate this build exists to fail on.
    for (const blank of ['', '   ', '\n']) {
      expect(missingDeployEnv({ ...deployed, VITE_WEB3AUTH_VERIFIER: blank })).toEqual([
        'VITE_WEB3AUTH_VERIFIER',
      ]);
      expect(missingDeployEnv({ ...deployed, VITE_WEB3AUTH_CLIENT_ID: blank })).toEqual([
        'VITE_WEB3AUTH_CLIENT_ID',
      ]);
      expect(missingDeployEnv({ ...deployed, VITE_GOOGLE_CLIENT_ID: blank })).toEqual([
        'VITE_GOOGLE_CLIENT_ID',
      ]);
    }
  });

  it('refuses a deployed build with no API origin, which would default to localhost', () => {
    for (const blank of ['', '   ']) {
      expect(missingDeployEnv({ ...deployed, VITE_API_URL: blank })).toEqual(['VITE_API_URL']);
    }
  });

  it('passes a fully configured deployment', () => {
    expect(missingDeployEnv(deployed)).toEqual([]);
  });

  it('exempts builds that name no deployment', () => {
    expect(missingDeployEnv({})).toEqual([]);
    expect(missingDeployEnv({ VITE_ENVIRONMENT: 'ci' })).toEqual([]);
  });
});

describe('shipsE2eHook', () => {
  it('refuses a deployed build carrying the e2e introspection flag', () => {
    for (const deployment of ['staging', 'production']) {
      for (const value of ['true', 'false', 'anything']) {
        expect(shipsE2eHook({ VITE_ENVIRONMENT: deployment, VITE_E2E_HOOK: value })).toBe(true);
      }
    }
  });

  it('passes a deployed build that leaves the flag unset or blank', () => {
    expect(shipsE2eHook({ VITE_ENVIRONMENT: 'staging' })).toBe(false);
    for (const blank of ['', '   ', '\n']) {
      expect(shipsE2eHook({ VITE_ENVIRONMENT: 'staging', VITE_E2E_HOOK: blank })).toBe(false);
    }
  });

  it('exempts the builds the suite itself runs against', () => {
    expect(shipsE2eHook({ VITE_ENVIRONMENT: 'ci', VITE_E2E_HOOK: 'true' })).toBe(false);
    expect(shipsE2eHook({ VITE_E2E_HOOK: 'true' })).toBe(false);
  });
});

describe('loginEnv', () => {
  const configured = {
    VITE_WEB3AUTH_CLIENT_ID: 'client',
    VITE_WEB3AUTH_VERIFIER: 'v',
    VITE_GOOGLE_CLIENT_ID: 'google-client',
  };

  it('keeps the two client IDs apart, which name unrelated registrations', () => {
    expect(loginEnv(configured)).toEqual({
      web3AuthClientId: 'client',
      googleClientId: 'google-client',
      verifier: 'v',
    });
  });

  it('trims the identifiers, which are sent to the providers verbatim', () => {
    expect(
      loginEnv({
        VITE_WEB3AUTH_CLIENT_ID: ' client\n',
        VITE_WEB3AUTH_VERIFIER: 'v ',
        VITE_GOOGLE_CLIENT_ID: '\tgoogle-client ',
      })
    ).toEqual({ web3AuthClientId: 'client', googleClientId: 'google-client', verifier: 'v' });
  });

  it('refuses a build missing one, naming it', () => {
    expect(() => loginEnv({ ...configured, VITE_WEB3AUTH_VERIFIER: undefined })).toThrow(
      /^VITE_WEB3AUTH_VERIFIER must be configured$/
    );
    // Otherwise the member meets Google's own `401 invalid_client`, which names
    // nothing they or an operator can act on. Whitespace is missing, not configured.
    for (const unset of [undefined, '', '   ', '\n']) {
      expect(() => loginEnv({ ...configured, VITE_GOOGLE_CLIENT_ID: unset })).toThrow(
        /^VITE_GOOGLE_CLIENT_ID must be configured$/
      );
    }
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
