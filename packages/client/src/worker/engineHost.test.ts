import { describe, expect, it } from 'vitest';
import { EngineHost } from './engineHost.js';
import type { EngineWasm } from './engineWasm.js';

/** Records the arguments the host constructs the wasm `EngineHandle` with. */
function recordingWasm(constructed: unknown[][]): EngineWasm {
  return {
    EngineHandle: class {
      constructor(...args: unknown[]) {
        constructed.push(args);
      }
    },
  } as unknown as EngineWasm;
}

describe('EngineHost', () => {
  it('hands the engine the API base URL so cold start can log in', () => {
    const constructed: unknown[][] = [];

    new EngineHost(
      recordingWasm(constructed),
      { seam: true },
      {
        apiBaseUrl: 'https://api.example.test',
        profile: 'ci',
        storageHeadroomBytes: 1024,
      }
    );

    const [seams, profile, apiBaseUrl, , , , storageHeadroomBytes] = constructed[0];
    expect(seams).toEqual({ seam: true });
    expect(profile).toBe('ci');
    expect(apiBaseUrl).toBe('https://api.example.test');
    expect(storageHeadroomBytes).toBe(1024);
  });

  it('forwards the content gateway configuration, bearerless', () => {
    const constructed: unknown[][] = [];

    new EngineHost(
      recordingWasm(constructed),
      {},
      {
        apiBaseUrl: 'https://api.example.test',
        acceleratorBaseUrl: 'https://accelerator.example.test',
        publicGateways: ['https://gateway.example.test'],
      }
    );

    const [, , , acceleratorBaseUrl, acceleratorBearer, publicGateways] = constructed[0];
    expect(acceleratorBaseUrl).toBe('https://accelerator.example.test');
    expect(publicGateways).toEqual(['https://gateway.example.test']);
    // A bearer is a session credential; no build-time surface supplies one.
    expect(acceleratorBearer).toBeUndefined();
  });

  it('leaves the gateway dormant when no endpoint is configured', () => {
    const constructed: unknown[][] = [];

    new EngineHost(recordingWasm(constructed), {}, { apiBaseUrl: 'https://api.example.test' });

    const [, , , acceleratorBaseUrl, , publicGateways] = constructed[0];
    expect(acceleratorBaseUrl).toBeUndefined();
    expect(publicGateways).toBeUndefined();
  });
});
