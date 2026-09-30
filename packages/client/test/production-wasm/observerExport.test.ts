import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

import { openIpnsRecordReader } from '../../src/index.js';

/** Where `apps/web`'s `build:wasm` writes the module the bundle ships. */
const shipped = resolve(import.meta.dirname, '../../../../apps/web/src/wasm');
const glueUrl = pathToFileURL(resolve(shipped, 'cipherbox_wasm.js'));

describe('the production engine module', () => {
  it('carries the engine exports and no record read', async () => {
    const glue = (await import(glueUrl.href)) as Record<string, unknown>;

    expect(typeof glue.identityFingerprint).toBe('function');
    expect(glue).not.toHaveProperty('readIpnsRecord');
    expect(glue).not.toHaveProperty('IpnsRecordReading');
  });

  it('gives the client reader a clear refusal', async () => {
    await expect(
      openIpnsRecordReader(glueUrl, readFileSync(resolve(shipped, 'cipherbox_wasm_bg.wasm')))
    ).rejects.toThrow('built with no `observer` feature');
  });
});
