import { describe, expect, it } from 'vitest';
import { EngineHost } from './engineHost.js';
import type { EngineWasm } from './engineWasm.js';

/** The arguments one `EngineHandle` construction crossed the WASM boundary with. */
interface Constructed {
  seams: unknown;
  profile: unknown;
  apiBaseUrl: unknown;
  acceleratorBaseUrl: unknown;
  acceleratorBearer: unknown;
  publicGateways: unknown;
  storageHeadroomBytes: unknown;
}

/** A wasm module whose `EngineHandle` records what it was constructed with. */
function recordingWasm(): { wasm: EngineWasm; constructed: Constructed[] } {
  const constructed: Constructed[] = [];
  const wasm = {
    EngineHandle: class {
      constructor(
        seams: unknown,
        profile: unknown,
        apiBaseUrl: unknown,
        acceleratorBaseUrl: unknown,
        acceleratorBearer: unknown,
        publicGateways: unknown,
        storageHeadroomBytes: unknown
      ) {
        constructed.push({
          seams,
          profile,
          apiBaseUrl,
          acceleratorBaseUrl,
          acceleratorBearer,
          publicGateways,
          storageHeadroomBytes,
        });
      }
    },
  } as unknown as EngineWasm;
  return { wasm, constructed };
}

describe('EngineHost', () => {
  it('hands the engine the API base URL so cold start can log in', () => {
    const { wasm, constructed } = recordingWasm();

    new EngineHost(
      wasm,
      { seam: true },
      {
        apiBaseUrl: 'https://api.example.test',
        profile: 'ci',
        storageHeadroomBytes: 1024,
      }
    );

    expect(constructed[0]).toMatchObject({
      seams: { seam: true },
      profile: 'ci',
      apiBaseUrl: 'https://api.example.test',
      storageHeadroomBytes: 1024,
    });
  });

  it('forwards the content gateway configuration, bearerless', () => {
    const { wasm, constructed } = recordingWasm();

    new EngineHost(
      wasm,
      {},
      {
        apiBaseUrl: 'https://api.example.test',
        acceleratorBaseUrl: 'https://accelerator.example.test',
        publicGateways: ['https://gateway.example.test'],
      }
    );

    expect(constructed[0]).toMatchObject({
      acceleratorBaseUrl: 'https://accelerator.example.test',
      publicGateways: ['https://gateway.example.test'],
    });
    expect(constructed[0].acceleratorBearer).toBeUndefined();
  });

  it('leaves the gateway dormant when no endpoint is configured', () => {
    const { wasm, constructed } = recordingWasm();

    new EngineHost(wasm, {}, { apiBaseUrl: 'https://api.example.test' });

    expect(constructed[0].acceleratorBaseUrl).toBeUndefined();
    expect(constructed[0].publicGateways).toBeUndefined();
  });
});
